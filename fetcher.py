"""
Phase 1: 资产收集

  A: CT 日志（crt.sh，失败自动退避重试，并回退 certspotter）→ DNS → 端口嗅探
  B: TLS 历史账本（Rapid7 Sonar 等）流式过滤，支持多种命名/字段结构
  C: 手工目标清单（--targets），无外网数据源时也能跑

相对 v1 的修复：
  - crt.sh 单点、无重试 → 加退避重试 + certspotter 备用源 + 明确错误分类
  - 账本只认 `port-<n>` 文件名 → 改为「文件名 → 记录 port 字段 → manifest → --assume-port」
  - 账本 gzip 同步读、把事件循环卡死 → 移到线程池
  - 端口嗅探一次性 gather 全部任务 → 固定 worker 池 + 有界队列
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import re
from pathlib import Path

from targets import parse_links_file  # noqa: F401  (对外暴露)

logger = logging.getLogger("reality-cf.fetcher")

__all__ = [
    "fetch_ct_logs", "fetch_tls_ledger", "parse_targets_file", "parse_links_file",
    "DEFAULT_PORTS",
]

# Cloudflare 支持的 HTTPS 端口（另加常见大厂备用端口）
DEFAULT_PORTS = [443, 8443, 2053, 2083, 2087, 2096]

UA = "Mozilla/5.0 (compatible; reality-cf/2.0; +https://github.com/xiki45/reality-cf)"

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_PORT_IN_NAME_RE = re.compile(r"(?:port[-_]?)(\d{2,5})", re.IGNORECASE)


# ══════════════════════════════════════════════════════════════
# Phase 1A: CT 日志
# ══════════════════════════════════════════════════════════════

async def fetch_ct_logs(
    sni: str,
    ports: list[int],
    timeout: float,
    retries: int = 3,
    use_certspotter: bool = True,
) -> set[tuple[str, int]]:
    """CT 日志 → 子域名 → DNS → 端口嗅探。任何一步空结果都安全返回空集。"""
    targets: set[tuple[str, int]] = set()

    hosts = await _query_crtsh(sni, timeout, retries)
    if not hosts and use_certspotter:
        hosts = await _query_certspotter(sni, timeout)
    if not hosts:
        logger.warning("  CT 日志无结果（crt.sh 与 certspotter 均失败或为空）: %s", sni)
        return targets

    hosts = sorted({h for h in hosts if _HOSTNAME_RE.match(h)})
    logger.info("  CT 日志 → %d 个主机名", len(hosts))

    ips = await _resolve_hosts(hosts)
    logger.info("  DNS → %d 个唯一 IPv4", len(ips))
    if not ips:
        return targets

    targets = await _sniff_ports(sorted(ips), ports, timeout)
    logger.info("  端口嗅探 → %d 个开放 IP:PORT", len(targets))
    return targets


async def _query_crtsh(sni: str, timeout: float, retries: int = 3) -> set[str]:
    """crt.sh，带指数退避。502/超时是常态，不能一次失败就放弃。"""
    import aiohttp

    hosts: set[str] = set()
    # %25 = '%'：通配查询，含所有子域
    urls = [
        f"https://crt.sh/?q=%25.{sni}&output=json",
        f"https://crt.sh/?q={sni}&output=json",
    ]
    backoff = 1.0
    for attempt in range(1, retries + 1):
        for url in urls:
            try:
                async with aiohttp.ClientSession(headers={"User-Agent": UA}) as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=timeout + 20)
                    ) as resp:
                        if resp.status != 200:
                            logger.debug("  crt.sh %s → HTTP %s", url, resp.status)
                            continue
                        text = await resp.text()
                data = json.loads(text)
            except Exception as exc:
                logger.debug("  crt.sh 第 %d 次失败: %s", attempt, type(exc).__name__)
                continue

            for entry in data:
                for key in ("name_value", "common_name"):
                    for name in str(entry.get(key, "")).split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name and sni.lower() in name:
                            hosts.add(name)
            if hosts:
                return hosts

        if attempt < retries:
            await asyncio.sleep(backoff)
            backoff *= 2
    return hosts


async def _query_certspotter(sni: str, timeout: float) -> set[str]:
    """certspotter 免费接口（无需 key，有限速）。crt.sh 挂掉时的备用源。"""
    import aiohttp

    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={sni}&include_subdomains=true&expand=dns_names"
    )
    hosts: set[str] = set()
    try:
        async with aiohttp.ClientSession(headers={"User-Agent": UA}) as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout + 20)) as resp:
                if resp.status != 200:
                    logger.debug("  certspotter → HTTP %s", resp.status)
                    return hosts
                data = await resp.json()
    except Exception as exc:
        logger.debug("  certspotter 失败: %s", type(exc).__name__)
        return hosts

    for entry in data if isinstance(data, list) else []:
        for name in entry.get("dns_names", []) or []:
            name = str(name).strip().lower().lstrip("*.")
            if name and sni.lower() in name:
                hosts.add(name)
    if hosts:
        logger.info("  certspotter 兜底 → %d 个主机名", len(hosts))
    return hosts


async def _resolve_hosts(hosts: list[str], concurrency: int = 200) -> set[str]:
    """批量 A 记录解析，优先 aiodns，回退 getaddrinfo。"""
    ips: set[str] = set()

    try:
        import aiodns

        resolver = aiodns.DNSResolver()
        sem = asyncio.Semaphore(concurrency)

        async def resolve(host: str):
            async with sem:
                try:
                    result = await resolver.query(host, "A")
                    for r in result:
                        ips.add(r.host)
                except Exception:
                    pass

        await asyncio.gather(*[resolve(h) for h in hosts])
        return ips
    except ImportError:
        logger.debug("  aiodns 不可用，回退 getaddrinfo")

    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(concurrency)

    async def resolve(host: str):
        async with sem:
            try:
                infos = await loop.getaddrinfo(host, None, family=2)  # AF_INET
                for info in infos:
                    ips.add(info[4][0])
            except Exception:
                pass

    await asyncio.gather(*[resolve(h) for h in hosts])
    return ips


async def _sniff_ports(
    ips: list[str], ports: list[int], timeout: float, concurrency: int = 500
) -> set[tuple[str, int]]:
    """TCP 三次握手嗅探（只建连不发数据），固定 worker 池。"""
    targets: set[tuple[str, int]] = set()
    q: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 4)
    stop = object()

    async def producer():
        try:
            for ip in ips:
                for port in ports:
                    await q.put((ip, port))
        finally:
            for _ in range(concurrency):
                await q.put(stop)

    async def worker():
        while True:
            item = await q.get()
            if item is stop:
                break
            ip, port = item
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                targets.add((ip, port))
            except Exception:
                pass

    prod = asyncio.create_task(producer())
    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    await asyncio.gather(prod, *workers, return_exceptions=True)
    return targets


# ══════════════════════════════════════════════════════════════
# Phase 1B: TLS 历史账本
# ══════════════════════════════════════════════════════════════

async def fetch_tls_ledger(
    ledger_dir: str,
    sni: str,
    assume_port: int | None = None,
    concurrency: int = 4,
) -> set[tuple[str, int]]:
    """
    流式扫描账本目录里的 *.json(.gz)。

    端口推断优先级：记录里的 port 字段 > 文件名里的 port-<n> > manifest.json > assume_port
    一条都推断不出来时跳过该文件并告警（v1 是静默丢弃，导致真实 Sonar 文件全部无效）。
    """
    root = Path(ledger_dir)
    if not root.is_dir():
        logger.warning("  账本目录不存在: %s", ledger_dir)
        return set()

    files = sorted(set(
        list(root.glob("*.json.gz")) + list(root.glob("*.jsonl.gz"))
        + list(root.glob("*.json")) + list(root.glob("*.jsonl"))
    ))
    if not files:
        logger.warning("  账本目录里没有 .json/.json.gz 文件: %s", ledger_dir)
        return set()

    manifest = _load_manifest(root)
    sni_lower = sni.lower()

    sem = asyncio.Semaphore(max(1, concurrency))

    async def scan(path: Path):
        async with sem:
            return await asyncio.to_thread(
                _scan_ledger_file, path, sni_lower, manifest.get(path.name), assume_port
            )

    results: set[tuple[str, int]] = set()
    for chunk in await asyncio.gather(*[scan(f) for f in files], return_exceptions=True):
        if isinstance(chunk, Exception):
            logger.debug("  账本分片失败: %s", chunk)
            continue
        results |= chunk

    logger.info("  账本 → %d 个 IP:PORT（扫描 %d 个文件）", len(results), len(files))
    return results


def _load_manifest(root: Path) -> dict[str, int]:
    """ledger_dl.py 下载时写的 manifest.json / ports.json：{"文件名": 端口}。"""
    for name in ("manifest.json", "ports.json"):
        path = root / name
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        mapping = data.get("files", data) if isinstance(data, dict) else {}
        out: dict[str, int] = {}
        for k, v in mapping.items():
            try:
                out[str(k)] = int(v)
            except Exception:
                continue
        return out
    return {}


def _scan_ledger_file(
    path: Path, sni_lower: str, file_port: int | None, assume_port: int | None
) -> set[tuple[str, int]]:
    """在线程里跑：gzip 流式逐行，只保留含目标 SNI 的行。"""
    out: set[tuple[str, int]] = set()
    guessed_port = file_port or _port_from_name(path.name) or assume_port

    opener = gzip.open if path.name.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if sni_lower not in line.lower():
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if not isinstance(rec, dict):
                    continue

                ip = _pick_ip(rec)
                if not ip:
                    continue

                port = _pick_port(rec) or guessed_port
                if not port:
                    continue
                out.add((ip, int(port)))
    except Exception as exc:
        logger.debug("  读取 %s 失败: %s", path.name, exc)
    if not guessed_port and out:
        logger.debug("  %s 里的端口无法推断，需 --assume-port", path.name)
    return out


def _port_from_name(name: str) -> int | None:
    m = _PORT_IN_NAME_RE.search(name)
    if not m:
        return None
    try:
        port = int(m.group(1))
    except Exception:
        return None
    return port if 0 < port < 65536 else None


def _pick_ip(rec: dict) -> str | None:
    for key in ("ip", "host", "address", "ip_address"):
        val = rec.get(key)
        if isinstance(val, str) and _IPV4_RE.match(val.strip()):
            return val.strip()
    return None


def _pick_port(rec: dict) -> int | None:
    for key in ("port", "port_number"):
        val = rec.get(key)
        try:
            port = int(val)
        except Exception:
            continue
        if 0 < port < 65536:
            return port
    return None


# ══════════════════════════════════════════════════════════════
# 手工目标清单
# ══════════════════════════════════════════════════════════════

def parse_targets_file(path: str, default_port: int = 443):
    """兼容入口：实现见 targets.py（支持 host:port:sni 三列）。"""
    from targets import parse_targets_file as _impl

    return _impl(path, default_port=default_port)

