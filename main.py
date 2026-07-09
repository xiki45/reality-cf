#!/usr/bin/env python3
"""
REALITY-CF 节点发现工具
基于 CT 日志 + TLS 账本，双重握手验证，精准筛选可薅 CF 羊毛的 REALITY 节点。

用法:
  python3 main.py --sni images.apple.com
  python3 main.py --sni swdist.apple.com --ledger scans/
  python3 main.py --sni-list snis.txt
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
CF_PROBE_DOMAIN = "speed.cloudflare.com"


async def interactive_mode(args):
    """交互式菜单模式"""

    PRESETS = {
        "1": ("images.apple.com", "Apple CDN"),
        "2": ("swdist.apple.com", "Apple Software"),
        "3": ("download.microsoft.com", "Microsoft CDN"),
    }

    try:
        from colorama import init, Fore, Style
        init(autoreset=True)
        C = Fore.CYAN; G = Fore.GREEN; Y = Fore.YELLOW; R = Style.RESET_ALL
    except ImportError:
        C = G = Y = R = ""

    print(f"\n{C}╔═══════════════════════════════════╗{R}")
    print(f"{C}║   REALITY-CF 节点发现 v1.0  ║{R}")
    print(f"{C}╚═══════════════════════════════════╝{R}\n")

    # Step 1: SNI
    print(f"{Y}📌 选择目标 SNI:{R}")
    for k, (sni, desc) in PRESETS.items():
        print(f"  {G}{k}{R}. {sni} ({desc})")
    print(f"  {G}c{R}. 自定义输入")
    choice = input(f"\n  选择 [1]: ").strip() or "1"

    snis = []
    if choice in PRESETS:
        snis.append(PRESETS[choice][0])
    else:
        custom = input("  输入 SNI: ").strip()
        if custom:
            snis.append(custom)

    if not snis:
        print(f"{Y}未输入 SNI，退出{R}")
        return

    # Step 2: CF 域名已内置 speed.cloudflare.com

    # Step 3: TLS ledger
    ledger = args.ledger
    if not ledger:
        use_ledger = input(f"\n{Y}📌 使用 TLS 账本? (y/N):{R} ").strip().lower()
        if use_ledger == "y":
            ledger = input("  TLS 账本目录: ").strip()

    # Step 4: Concurrency
    concurrency = args.concurrency
    custom_cc = input(f"\n{Y}📌 并发数 [500]:{R} ").strip()
    if custom_cc:
        concurrency = int(custom_cc)

    # Step 5: Ports
    ports_str = args.ports
    custom_ports = input(f"{Y}📌 端口 [{ports_str}]:{R} ").strip()
    if custom_ports:
        ports_str = custom_ports

    ports = [int(p) for p in ports_str.split(",")]

    # ── 运行 ──
    print(f"\n{G}▶ 开始抓取...{R}")
    print(f"  SNI: {G}{', '.join(snis)}{R}")
    print(f"  CF:  {G}{CF_PROBE_DOMAIN}{R}")
    print(f"  并发: {concurrency}  端口: {ports_str}\n")

    from fetcher  import fetch_ct_logs, fetch_tls_ledger
    from verifier import verify_batch
    from reporter import Reporter

    all_targets: set[tuple[str, int]] = set()

    for sni in snis:
        print(f"  [Phase 1A] CT 日志: {sni}")
        targets = await fetch_ct_logs(sni, ports, args.timeout)
        all_targets.update(targets)
        print(f"    → {C}{len(targets)}{R} 候选")

    if ledger:
        for sni in snis:
            print(f"  [Phase 1B] TLS 账本: {sni}")
            targets = await fetch_tls_ledger(ledger, sni)
            all_targets.update(targets)
            print(f"    → {C}{len(targets)}{R} 候选")

    all_targets = all_targets & all_targets  # no-op type hint

    if not all_targets:
        print(f"{Y}  未获取到候选节点{R}")
        return

    target_list = list(all_targets)
    print(f"\n  {G}总计 {len(target_list)} 个待验证{R}\n")

    reporter = Reporter(args.output)
    reporter.start()

    print(f"  [Phase 2] 双重 TLS 验证 (并发 {concurrency})")
    async for result in verify_batch(
        target_list, snis, CF_PROBE_DOMAIN,
        concurrency=concurrency, timeout=args.timeout,
        redundancy_check=not args.no_redundancy,
    ):
        reporter.on_result(result)

    reporter.finish()
    print(f"\n{G}✅ 完成 — 结果 → {args.output}{R}\n")


async def main():
    parser = argparse.ArgumentParser(description="REALITY-CF 节点发现")
    parser.add_argument("--sni", help="目标大厂 SNI (如 images.apple.com)")
    parser.add_argument("--sni-list", help="SNI 列表文件，一行一个")
    parser.add_argument("--ledger", help="TLS 账本目录 (含 port-*-tls.json.gz)")
    parser.add_argument("--ports", default="443,8443,2053,2083,2096,2443",
                        help="伴随嗅探端口 (默认 443,8443,2053,2083,2096,2443)")
    parser.add_argument("--concurrency", type=int, default=500, help="验证并发数 (默认 500)")
    parser.add_argument("--timeout", type=float, default=3.0, help="单次握手超时 (默认 3s)")
    parser.add_argument("--output", default="vuln_reality_cf_report.json", help="输出文件")
    parser.add_argument("--no-redundancy", action="store_true", help="关闭冗余检测")
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
        # 交互模式
        await interactive_mode(args)
        return

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
        target_list, snis, CF_PROBE_DOMAIN,
        concurrency=args.concurrency,
        timeout=args.timeout,
        redundancy_check=not args.no_redundancy,
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
