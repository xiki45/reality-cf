"""
Phase 2: 双重 TLS 交叉验证模块 + Phase 3 蜜罐过滤
高并发 asyncio + Semaphore，任意一步失败即丢弃。
"""

import asyncio, ssl, logging, random, string
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("reality-cf.verifier")


async def verify_single(
    ip: str, port: int, target_sni: str, my_cf_domain: str,
    timeout: float = 3.0, honeypot_check: bool = True
) -> dict | None:
    """
    对单个 IP:PORT 执行双重握手验证。
    返回 dict 表示漏洞确认，None 表示丢弃。
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # ══════════════════════════════════════
    # Step 1: REALITY 身份实锤
    # ══════════════════════════════════════
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except Exception:
        return None

    try:
        loop = asyncio.get_event_loop()
        ssl_transport = await loop.start_tls(
            writer.transport, protocol_factory=None,
            sslcontext=ctx, server_hostname=target_sni
        )
        # 关键: binary_form=True 取 DER 格式
        der_cert = ssl_transport.get_extra_info("peercert", binary_form=True)
        writer.close()
        await writer.wait_closed()
    except Exception:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return None

    if not der_cert:
        return None

    # 解析证书 CN
    try:
        cert = x509.load_der_x509_certificate(der_cert, default_backend())
        cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not cns:
            return None
        common_name = cns[0].value
    except Exception:
        return None

    # 模糊匹配 CN
    if target_sni.lower() not in str(common_name).lower():
        return None

    # ══════════════════════════════════════
    # Step 2: CF 反代漏洞判定
    # ══════════════════════════════════════
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
    except Exception:
        return None

    try:
        ssl_transport = await loop.start_tls(
            writer.transport, protocol_factory=None,
            sslcontext=ctx, server_hostname=my_cf_domain
        )
        req = f"GET / HTTP/1.1\r\nHost: {my_cf_domain}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        res_text = response.decode("utf-8", errors="ignore").lower()
        writer.close()
        await writer.wait_closed()
    except Exception:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return None

    if "server: cloudflare" not in res_text and "cf-ray" not in res_text:
        return None

    # ══════════════════════════════════════
    # Phase 3: 蜜罐过滤
    # ══════════════════════════════════════
    if honeypot_check and await _is_honeypot(ip, port, timeout, loop):
        logger.debug(f"  蜜罐过滤: {ip}:{port}")
        return None

    return {
        "ip": ip,
        "port": port,
        "target_sni": target_sni,
        "common_name": str(common_name),
        "status": "VULNERABLE",
    }


async def _is_honeypot(ip: str, port: int, timeout: float, loop) -> bool:
    """随机混淆 SNI 验证: 若仍返回 CF 头 → 蜜罐"""
    random_sni = "".join(random.choices(string.ascii_lowercase, k=10)) + ".org"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        await loop.start_tls(
            writer.transport, protocol_factory=None,
            sslcontext=ctx, server_hostname=random_sni
        )
        req = f"GET / HTTP/1.1\r\nHost: {random_sni}\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(512), timeout=timeout)
        res_text = response.decode("utf-8", errors="ignore").lower()
        writer.close()
        await writer.wait_closed()

        if "server: cloudflare" in res_text or "cf-ray" in res_text:
            return True  # 蜜罐
    except Exception:
        pass

    return False


async def verify_batch(
    targets: list[tuple[str, int]], target_snis: list[str],
    my_cf_domain: str, concurrency: int = 500,
    timeout: float = 3.0, honeypot_check: bool = True,
):
    """
    批量验证，流式 yield 结果。
    """
    sem = asyncio.Semaphore(concurrency)
    queue = asyncio.Queue()
    all_done = asyncio.Event()

    # 投喂任务
    for ip, port in targets:
        for sni in target_snis:
            await queue.put((ip, port, sni))

    async def worker():
        while True:
            try:
                ip, port, sni = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            async with sem:
                result = await verify_single(
                    ip, port, sni, my_cf_domain,
                    timeout=timeout, honeypot_check=honeypot_check,
                )
                if result:
                    yield result
                queue.task_done()

    # 跑 worker 并发
    tasks = []
    results_queue = asyncio.Queue()

    async def run_worker():
        async for r in worker():
            await results_queue.put(r)

    for _ in range(min(concurrency, len(targets) * len(target_snis))):
        tasks.append(asyncio.create_task(run_worker()))

    # 等待所有 worker 完成后，从 results_queue 取出
    await asyncio.gather(*tasks, return_exceptions=True)

    all_results = []
    while not results_queue.empty():
        all_results.append(await results_queue.get())

    for r in all_results:
        yield r
