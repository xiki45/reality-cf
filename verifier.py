"""
Phase 2 + Phase 3: 双重 TLS 交叉验证 / 反蜜罐 / 批量调度

相对 v1 的修复（每一条都有实测依据，见 tests/）：
  1. 握手统一走 asyncio.open_connection(ssl=ctx, server_hostname=...)；
     v1 的 loop.start_tls(protocol_factory=None) 在 Python 3.9+ 上直接 TypeError
     （真参数名是 protocol，且必须传 Protocol 对象），异常被吞后每个目标必返回 None。
  2. 证书取 get_extra_info("ssl_object").getpeercert(binary_form=True)；
     v1 的 get_extra_info("peercert") 在 CERT_NONE 下恒为 {}（dict 形态），
     binary_form=True 只是被当成 default 位置参数，所以 DER 永远拿不到。
  3. 主机名匹配改用 SAN（RFC 6125 通配），CN 仅在证书没有 SAN 时回退：
     真实证书 CN 与 SNI 并不一致（images.apple.com 的 CN 是 www.apple.com，
     swdist.apple.com 的 CN 是 swcdn.apple.com），v1 的 `sni in CN` 会否掉它们。
  4. SSLContext 进程级复用；v1 每目标新建 2~3 次（实测 4.97ms/次且阻塞事件循环，
     吞吐被压到 200 target/s）。
  5. verify_batch 真流式：谁先完成谁先吐；v1 会把结果缓存到全部结束再交出去。
  6. 反蜜罐探针改用 RFC 2606 保留域 .invalid，避免随机 .org 恰好是真实 CF 站点。
"""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import string
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

logger = logging.getLogger("reality-cf.verifier")

__all__ = [
    "Stats", "reset_stats", "get_stats",
    "cert_match", "verify_single", "verify_batch",
    "HONEYPOT_SNI_SUFFIX",
]

# ══════════════════════════════════════════════════════════════
# 统计：让「为什么没命中」可观测，而不是静默 return None
# ══════════════════════════════════════════════════════════════

@dataclass
class Stats:
    total: int = 0            # 进入验证的目标数
    probe_fail: int = 0       # Step 1 连不上 / TLS 握手失败
    no_cert: int = 0          # 握手成功但拿不到证书
    name_mismatch: int = 0    # 证书与 target_sni 不匹配（不是该大厂的中继）
    step2_tls_fail: int = 0   # Step 2 换 SNI 握手失败（target 不认这个 SNI）
    no_cf: int = 0            # Step 2 通了但没有 CF 特征头
    honeypot: int = 0         # 随机 SNI 也回 CF 头 → 蜜罐/无差别反代
    hit: int = 0              # 确认命中
    errors: dict = field(default_factory=dict)

    def dump(self) -> dict:
        return {
            "total": self.total,
            "probe_fail": self.probe_fail,
            "no_cert": self.no_cert,
            "name_mismatch": self.name_mismatch,
            "step2_tls_fail": self.step2_tls_fail,
            "no_cf": self.no_cf,
            "honeypot": self.honeypot,
            "hit": self.hit,
            "errors": dict(self.errors),
        }


_STATS = Stats()


def reset_stats() -> Stats:
    global _STATS
    _STATS = Stats()
    return _STATS


def get_stats() -> Stats:
    return _STATS


def _bump(field_name: str) -> None:
    setattr(_STATS, field_name, getattr(_STATS, field_name) + 1)


# ══════════════════════════════════════════════════════════════
# TLS 基础设施
# ══════════════════════════════════════════════════════════════

_TLS_CTX: ssl.SSLContext | None = None


def _ctx() -> ssl.SSLContext:
    """进程级复用。CERT_NONE + check_hostname=False：我们只读证书内容，不校验信任链。"""
    global _TLS_CTX
    if _TLS_CTX is None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:  # 个别 OpenSSL 构建不支持
            pass
        _TLS_CTX = ctx
    return _TLS_CTX


async def _tls_probe(ip: str, port: int, sni: str, timeout: float):
    """建连 + TLS 握手。返回 (reader, writer, der_cert, tls_info)。"""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=_ctx(), server_hostname=sni),
        timeout=timeout,
    )
    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj is not None else None
        info = {
            "tls_version": sslobj.version() if sslobj is not None else None,
            "cipher": (sslobj.cipher() or (None,))[0] if sslobj is not None else None,
            "alpn": (sslobj.selected_alpn_protocol() if sslobj is not None else None),
        }
        return reader, writer, der, info
    except Exception:
        writer.close()
        raise


async def _read_head(reader: asyncio.StreamReader, limit: int, timeout: float) -> bytes:
    """读到 HTTP 头结束（\\r\\n\\r\\n）或 limit/超时为止。"""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    buf = bytearray()
    while len(buf) < limit:
        remain = deadline - loop.time()
        if remain <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(1024), timeout=remain)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf:
            break
    return bytes(buf)


def _parse_head(raw: bytes) -> tuple[str, dict, str]:
    text = raw.decode("iso-8859-1", "replace")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    status_line = lines[0].strip() if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        key, sep, val = line.partition(":")
        if sep and key.strip():
            headers[key.strip().lower()] = val.strip()
    return status_line, headers, body


def _is_cf(headers: dict) -> bool:
    return bool(headers.get("cf-ray")) or "cloudflare" in headers.get("server", "").lower()


# ══════════════════════════════════════════════════════════════
# 证书名匹配（SAN 优先，CN 回退）
# ══════════════════════════════════════════════════════════════

def _dnsname_match(pattern: str, hostname: str) -> bool:
    """RFC 6125 风格：`*.apple.com` 只匹配一级子域；大小写无关；忽略尾点。"""
    if not pattern or not hostname:
        return False
    pat = pattern.strip().lower().rstrip(".")
    host = hostname.strip().lower().rstrip(".")
    if pat == host:
        return True
    if pat.startswith("*."):
        suffix = pat[1:]                     # ".apple.com"
        if not host.endswith(suffix):
            return False
        label = host[: -len(suffix)]
        return bool(label) and "." not in label
    return False


def cert_names(der_cert: bytes | None) -> list[str]:
    """证书里所有 DNS 名（SAN 优先，CN 追加）。用于观察对端 dest 的真实身份。"""
    if not der_cert:
        return []
    try:
        cert = x509.load_der_x509_certificate(der_cert)
    except Exception:
        return []
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names += [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    except Exception:
        pass
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            v = attr.value.lower()
            if v not in names:
                names.append(v)
    except Exception:
        pass
    return names


#: 证书不匹配时的回调 (ip, port, cert_names)，供 monitor 记录 dest 轮换
MISS_HOOK = None


def cert_match(der: bytes, sni: str) -> tuple[bool, str, str]:
    """返回 (是否匹配, 命中的名字, 来源 SAN/CN)。"""
    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception:
        return False, "", "parse_error"

    san_names: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_names = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        san_names = []

    for name in san_names:
        if _dnsname_match(name, sni):
            return True, name, "SAN"

    if not san_names:  # 只有没有 SAN 的旧证书才看 CN（浏览器同样行为）
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            cn = attr.value
            if _dnsname_match(cn, sni) or sni.lower() in cn.lower():
                return True, cn, "CN"

    return False, (san_names[0] if san_names else ""), "SAN"


# ══════════════════════════════════════════════════════════════
# 单目标验证
# ══════════════════════════════════════════════════════════════

HONEYPOT_SNI_SUFFIX = ".invalid"


async def verify_single(
    ip: str,
    port: int,
    target_sni: str,
    my_cf_domain: str,
    timeout: float = 3.0,
    redundancy_check: bool = True,
) -> dict | None:
    """
    对单个 IP:PORT 执行双重握手验证。

    Step 1  用大厂 SNI 握手，确认该端口确实在向该大厂中转 TLS（证书 SAN 必须匹配）。
    Step 2  换成自己的 CF 域名再握手 + 发一个最小 HTTP 请求，看是否回 CF 特征头。
    Step 3  用保留域随机 SNI 再试，若照样回 CF 头 → 蜜罐 / 无差别反代，丢弃。
    """
    _STATS.total += 1

    # ── Step 1: 证书身份 ──
    try:
        reader, writer, der, tls_info = await _tls_probe(ip, port, target_sni, timeout)
    except Exception:
        _bump("probe_fail")
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass

    if not der:
        _bump("no_cert")
        return None

    ok, matched_name, matched_by = cert_match(der, target_sni)
    if not ok:
        _bump("name_mismatch")
        if MISS_HOOK is not None:
            try:
                MISS_HOOK(ip, port, cert_names(der))
            except Exception:
                pass
        return None

    # ── Step 2: CF 反代特征 ──
    try:
        reader, writer, _, _ = await _tls_probe(ip, port, my_cf_domain, timeout)
    except Exception:
        _bump("step2_tls_fail")
        return None

    try:
        writer.write(
            f"GET / HTTP/1.1\r\nHost: {my_cf_domain}\r\n"
            f"User-Agent: reality-cf/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        raw = await _read_head(reader, 8192, timeout)
    except Exception:
        _bump("no_cf")
        return None
    finally:
        try:
            writer.close()
        except Exception:
            pass

    status_line, headers, _ = _parse_head(raw)
    if not _is_cf(headers):
        _bump("no_cf")
        return None

    # ── Step 3: 反蜜罐 ──
    if redundancy_check and await _is_honeypot(ip, port, timeout):
        _bump("honeypot")
        return None

    _bump("hit")
    cf_ray = headers.get("cf-ray")
    return {
        "ip": ip,
        "port": port,
        "target_sni": target_sni,
        "common_name": matched_name,
        "matched_by": matched_by,
        "status": "AVAILABLE",
        "confidence": "high" if cf_ray else "medium",
        "evidence": {
            "cf_domain": my_cf_domain,
            "http_status": status_line,
            "cf_ray": cf_ray,
            "server": headers.get("server"),
            "tls_version": tls_info.get("tls_version"),
            "cipher": tls_info.get("cipher"),
            "alpn": tls_info.get("alpn"),
        },
    }


async def _is_honeypot(ip: str, port: int, timeout: float) -> bool:
    """用 RFC 2606 保留域做随机 SNI 探针；任何真实 CF 站点都不可能响应它。"""
    sni = "".join(random.choices(string.ascii_lowercase, k=12)) + HONEYPOT_SNI_SUFFIX
    try:
        reader, writer, _, _ = await _tls_probe(ip, port, sni, timeout)
    except Exception:
        return False  # 握手被拒 = 正常表现

    try:
        writer.write(
            f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: reality-cf/2.0\r\n"
            f"Accept: */*\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
        raw = await _read_head(reader, 2048, timeout)
    except Exception:
        return False
    finally:
        try:
            writer.close()
        except Exception:
            pass

    _, headers, _ = _parse_head(raw)
    return _is_cf(headers)


# ══════════════════════════════════════════════════════════════
# 批量调度（真流式）
# ══════════════════════════════════════════════════════════════

async def verify_batch(
    targets,
    target_snis: list[str],
    my_cf_domain: str,
    concurrency: int = 500,
    timeout: float = 3.0,
    redundancy_check: bool = True,
):
    """
    并发验证，谁先完成谁先 yield。

    固定数量 worker + 有界队列：目标再多也不会一次性建出 N 个 Task（v1 会）。
    """
    snis = [s for s in target_snis if s]
    # 注意：snis 可以为空 —— 只要每个 target 自带 SNI（--links / host:port:sni）就能跑。

    nworkers = max(1, int(concurrency))
    in_q: asyncio.Queue = asyncio.Queue(maxsize=nworkers * 4)
    out_q: asyncio.Queue = asyncio.Queue()
    stop = object()

    async def producer():
        try:
            for target in targets:
                # 支持 (ip, port) 与 (ip, port, sni) 两种形态：
                # 后者是「不盲扫」——目标只跟它自己的 SNI 配对，不做笛卡尔积。
                ip, port = target[0], target[1]
                own = target[2] if len(target) > 2 else ""
                for sni in ([own] if own else snis):
                    await in_q.put((ip, port, sni))
        finally:
            for _ in range(nworkers):
                await in_q.put(stop)

    async def worker():
        while True:
            item = await in_q.get()
            if item is stop:
                break
            ip, port, sni = item
            try:
                result = await verify_single(
                    ip, port, sni, my_cf_domain,
                    timeout=timeout, redundancy_check=redundancy_check,
                )
            except Exception as exc:  # 单个目标的问题不该终止整批
                _STATS.errors[type(exc).__name__] = _STATS.errors.get(type(exc).__name__, 0) + 1
                result = None
            await out_q.put(("result", result))
        await out_q.put(("done", None))

    prod_task = asyncio.create_task(producer())
    worker_tasks = [asyncio.create_task(worker()) for _ in range(nworkers)]

    finished = 0
    try:
        while finished < nworkers:
            kind, payload = await out_q.get()
            if kind == "done":
                finished += 1
            elif payload is not None:
                yield payload
    finally:
        await asyncio.gather(prod_task, *worker_tasks, return_exceptions=True)
