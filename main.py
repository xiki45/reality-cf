#!/usr/bin/env python3
"""
REALITY-CF 漏洞精准抓取工具
基于 CT 日志 + TLS 账本，双重握手验证，精准筛选可薅 CF 羊毛的 REALITY 节点。

用法:
  python3 main.py --sni images.apple.com --cf-domain xyz.899920.xyz
  python3 main.py --sni swdist.apple.com --cf-domain xyz.899920.xyz --ledger scans/
  python3 main.py --sni-list snis.txt --cf-domain xyz.899920.xyz
"""

import sys, os, signal, argparse, resource, asyncio, logging
from pathlib import Path

# ── 文件描述符提升 ──
try:
    resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
except Exception:
    pass

from fetcher   import fetch_ct_logs, fetch_tls_ledger
from verifier  import verify_batch
from reporter  import Reporter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("reality-cf")

DEFAULT_PORTS = [443, 8443, 2053, 2083, 2096, 2443]


async def main():
    parser = argparse.ArgumentParser(description="REALITY-CF 漏洞精准抓取")
    parser.add_argument("--sni", help="目标大厂 SNI (如 images.apple.com)")
    parser.add_argument("--sni-list", help="SNI 列表文件，一行一个")
    parser.add_argument("--cf-domain", required=True, help="用户私有 CF 域名 (开小黄云)")
    parser.add_argument("--ledger", help="TLS 账本目录 (含 port-*-tls.json.gz)")
    parser.add_argument("--ports", default="443,8443,2053,2083,2096,2443",
                        help="伴随嗅探端口 (默认 443,8443,2053,2083,2096,2443)")
    parser.add_argument("--concurrency", type=int, default=500, help="验证并发数 (默认 500)")
    parser.add_argument("--timeout", type=float, default=3.0, help="单次握手超时 (默认 3s)")
    parser.add_argument("--output", default="vuln_reality_cf_report.json", help="输出文件")
    parser.add_argument("--no-honeypot", action="store_true", help="关闭蜜罐过滤")
    args = parser.parse_args()

    # ── SNI 列表 ──
    snis = []
    if args.sni:
        snis.append(args.sni.strip())
    if args.sni_list:
        with open(args.sni_list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    snis.append(line)
    if not snis:
        logger.error("请提供 --sni 或 --sni-list")
        sys.exit(1)

    ports = [int(p) for p in args.ports.split(",")]

    # ── 任务队列 ──
    all_targets: set[tuple[str, int]] = set()

    # Phase 1A: CT 日志
    for sni in snis:
        logger.info(f"[Phase 1A] CT 日志: {sni}")
        targets = await fetch_ct_logs(sni, ports, args.timeout)
        all_targets.update(targets)
        logger.info(f"  → 获取 {len(targets)} 候选")

    # Phase 1B: TLS 账本
    if args.ledger:
        for sni in snis:
            logger.info(f"[Phase 1B] TLS 账本: {sni}")
            targets = await fetch_tls_ledger(args.ledger, sni)
            all_targets.update(targets)
            logger.info(f"  → 获取 {len(targets)} 候选")

    if not all_targets:
        logger.error("未获取到任何候选节点，请检查 SNI 或网络")
        sys.exit(1)

    target_list = list(all_targets)
    logger.info(f"总计 {len(target_list)} 个待验证 IP:PORT")

    # ── Phase 2 + 3: 验证 + 输出 ──
    reporter = Reporter(args.output)
    reporter.start()

    logger.info(f"[Phase 2] 双重 TLS 交叉验证 (并发 {args.concurrency})")
    async for result in verify_batch(
        target_list, snis, args.cf_domain,
        concurrency=args.concurrency,
        timeout=args.timeout,
        honeypot_check=not args.no_honeypot,
    ):
        reporter.on_result(result)

    reporter.finish()
    logger.info(f"完成 — 结果 → {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
        logger.info("用户中断")
