"""
Phase 1: 资产收集模块
  A: CT 日志 + DNS + 伴随端口嗅探
  B: TLS 历史账本流式过滤
"""

import asyncio, ssl, gzip, json, logging, re
from pathlib import Path

logger = logging.getLogger("reality-cf.fetcher")

# ── Phase 1A: CT 日志 ──

async def fetch_ct_logs(sni: str, ports: list[int], timeout: float) -> set[tuple[str, int]]:
    """从 crt.sh 获取子域名 → DNS 解析 → 端口嗅探"""
    targets: set[tuple[str, int]] = set()

    # 1. 查 crt.sh
    subdomains = await _query_crtsh(sni, timeout)
    if not subdomains:
        logger.warning(f"  crt.sh 无结果: {sni}")
        return targets

    # 2. 去重
    subdomains = list(set(subdomains))
    logger.info(f"  crt.sh → {len(subdomains)} 个子域")

    # 3. 异步 DNS 解析
    ips = await _resolve_domains(subdomains)
    logger.info(f"  DNS → {len(ips)} 个唯一 IP")

    # 4. 伴随端口嗅探
    targets = await _sniff_ports(list(ips), ports, timeout)
    logger.info(f"  端口嗅探 → {len(targets)} 个开放")

    return targets


async def _query_crtsh(sni: str, timeout: float) -> list[str]:
    """查询 crt.sh 获取子域名列表"""
    import aiohttp
    url = f"https://crt.sh/?q=%25.{sni}&output=json"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout+5)) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
    except Exception as e:
        logger.debug(f"  crt.sh 请求失败: {e}")
        return []

    domains = set()
    for entry in data:
        for key in ("name_value", "common_name"):
            val = entry.get(key, "")
            if val:
                for name in val.split("\n"):
                    name = name.strip().lower()
                    if name and sni.lower() in name:
                        domains.add(name)
    return list(domains)


async def _resolve_domains(domains: list[str]) -> set[str]:
    """批量异步 DNS 解析"""
    ips = set()
    try:
        import aiodns
        resolver = aiodns.DNSResolver()
        sem = asyncio.Semaphore(200)

        async def resolve(domain: str):
            async with sem:
                try:
                    result = await resolver.query(domain, "A")
                    for r in result:
                        ips.add(r.host)
                except Exception:
                    pass

        await asyncio.gather(*[resolve(d) for d in domains])
    except ImportError:
        # 降级: 用 asyncio 的 getaddrinfo
        sem = asyncio.Semaphore(200)

        async def resolve(domain: str):
            async with sem:
                try:
                    result = await asyncio.get_event_loop().getaddrinfo(domain, None)
                    for r in result:
                        if r[0].name == "AF_INET":
                            ips.add(r[4][0])
                except Exception:
                    pass

        await asyncio.gather(*[resolve(d) for d in domains])

    return ips


async def _sniff_ports(ips: list[str], ports: list[int], timeout: float) -> set[tuple[str, int]]:
    """异步 TCP 端口嗅探"""
    targets: set[tuple[str, int]] = set()
    sem = asyncio.Semaphore(500)

    async def probe(ip: str, port: int):
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                targets.add((ip, port))
            except Exception:
                pass

    tasks = [probe(ip, port) for ip in ips for port in ports]
    await asyncio.gather(*tasks)
    return targets


# ── Phase 1B: TLS 历史账本 ──

async def fetch_tls_ledger(ledger_dir: str, sni: str) -> set[tuple[str, int]]:
    """流式读取 TLS 账本，匹配 SNI"""
    targets: set[tuple[str, int]] = set()
    path = Path(ledger_dir)
    sni_lower = sni.lower()
    pattern = re.compile(rf"(?:server_name|common_name|cn).*?{re.escape(sni_lower)}", re.IGNORECASE)

    sem = asyncio.Semaphore(4)  # 限制并发文件读取

    async def process_file(filepath: Path, port: int):
        async with sem:
            try:
                with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if sni_lower in line.lower() and (pattern.search(line) or sni_lower in line.lower()):
                            try:
                                record = json.loads(line)
                                ip = record.get("ip", "")
                                if ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                                    targets.add((ip.strip(), port))
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                logger.debug(f"  读取 {filepath.name} 失败: {e}")

    # 扫描账本目录
    ledger_path = Path(ledger_dir)
    tasks = []
    for f in ledger_path.glob("*.json.gz"):
        port_match = re.search(r"port-(\d+)", f.name)
        if port_match:
            port = int(port_match.group(1))
            tasks.append(process_file(f, port))

    if tasks:
        await asyncio.gather(*tasks)
    else:
        logger.warning(f"  未找到 .json.gz 账本文件于 {ledger_dir}")

    return targets
