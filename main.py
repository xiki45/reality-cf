#!/usr/bin/env python3
"""
REALITY-CF 节点发现

发现「target 落在 Cloudflare 后面、且会把失败认证流量原样转发」的 REALITY 节点，
即 Xray 官方文档所述「服务器实际沦为 CF 端口转发器、可被扫描滥用」的那一类。

用法:
  reality-cf --sni images.apple.com --cf-domain my.domain.com
  reality-cf --sni images.apple.com --targets ips.txt --cf-domain my.domain.com
  reality-cf --sni-list snis.txt --ledger ./scans --cf-domain my.domain.com
  reality-cf                      # 无参数 → 交互菜单

v2 修复要点：
  - 新增 --cf-domain（v1 文档写了但 argparse 里没有，所有示例都 exit=2）
  - 新增 --targets（公网数据源不可用时唯一直通路径）
  - --ledger 不再被 --auto-ledger 覆盖（v1 会把它冲成 None）
  - 数据源全部为空时给出可操作的指引，而不是 sys.exit(1)
  - 输出统计（各阶段丢弃原因），0 命中时能定位到具体环节
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from fetcher import DEFAULT_PORTS, fetch_ct_logs, fetch_tls_ledger, parse_targets_file
from reporter import Reporter, print_summary
from verifier import get_stats, reset_stats, verify_batch

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("reality-cf")

CF_PROBE_DOMAIN = "speed.cloudflare.com"
PRESETS = [
    ("images.apple.com", "Apple CDN"),
    ("swdist.apple.com", "Apple Software"),
    ("download.microsoft.com", "Microsoft CDN"),
]


# ══════════════════════════════════════════════════════════════
# 资产收集编排
# ══════════════════════════════════════════════════════════════

async def collect_targets(args, snis: list[str], ports: list[int]) -> set[tuple[str, int]]:
    targets: set[tuple[str, int]] = set()

    # C: 手工清单（最先加载，保证即使外网全挂也能跑）
    for path in args.targets or []:
        try:
            got = parse_targets_file(path, default_port=ports[0])
            logger.info("[Phase 1C] 目标清单 %s → %d 个 IP:PORT", path, len(got))
            targets.update(got)
        except FileNotFoundError:
            logger.error("目标清单不存在: %s", path)
        except Exception as exc:
            logger.error("目标清单解析失败 %s: %s", path, exc)

    # A: CT 日志
    if not args.no_ct:
        for sni in snis:
            logger.info("[Phase 1A] CT 日志: %s", sni)
            got = await fetch_ct_logs(sni, ports, args.timeout, retries=args.ct_retries)
            logger.info("  → %d 个候选", len(got))
            targets.update(got)

    # B: TLS 账本
    if not args.no_ledger:
        ledger_dir = args.ledger
        if not ledger_dir and args.auto_ledger:
            from ledger_dl import download_ledger

            ledger_dir = await download_ledger(args.ledger_cache, ports, limit=args.ledger_limit)
        if ledger_dir:
            for sni in snis:
                logger.info("[Phase 1B] TLS 账本: %s", sni)
                got = await fetch_tls_ledger(ledger_dir, sni, assume_port=args.assume_port)
                logger.info("  → %d 个候选", len(got))
                targets.update(got)
        elif args.ledger:
            logger.error("账本目录不可用: %s", args.ledger)

    return targets


def _empty_hint() -> str:
    return (
        "没有拿到任何候选目标。三条路任选其一：\n"
        "  1) 给 IP 清单（最可靠）：reality-cf --sni <大厂域名> --targets ips.txt --cf-domain <你的CF域名>\n"
        "  2) 给账本目录：--ledger <目录>（目录内放 *.json.gz，每条含 ip/port/server_name）\n"
        "  3) 修好外网数据源：crt.sh 或配置 SONAR_API_KEY 后加 --auto-ledger\n"
        "  注：CT 日志只能枚举域名（不含 IP），单靠它扫不到第三方中转节点。"
    )


# ══════════════════════════════════════════════════════════════
# 运行
# ══════════════════════════════════════════════════════════════

async def run(args) -> int:
    snis = _load_snis(args)
    ports = _parse_ports(args.ports)

    logger.info("目标 SNI: %s | CF 域名: %s | 端口: %s",
                ", ".join(snis), args.cf_domain, ",".join(map(str, ports)))

    targets = await collect_targets(args, snis, ports)
    if not targets:
        print(_empty_hint(), file=sys.stderr)
        return 2

    logger.info("总计 %d 个待验证 IP:PORT（并发 %d，超时 %.1fs）",
                len(targets), args.concurrency, args.timeout)

    reset_stats()
    reporter = Reporter(args.output, fmt=args.format)
    reporter.start()

    try:
        async for result in verify_batch(
            sorted(targets), snis, args.cf_domain,
            concurrency=args.concurrency,
            timeout=args.timeout,
            redundancy_check=not args.no_redundancy,
        ):
            reporter.on_result(result)
    except KeyboardInterrupt:
        reporter.abort()
        logger.warning("已中断，已发现的结果已落盘 → %s", args.output)
        print_summary(get_stats().dump())
        return 130

    reporter.finish()
    print_summary(get_stats().dump())
    return 0 if reporter.count or get_stats().total else 1


def _load_snis(args) -> list[str]:
    snis: list[str] = []
    if args.sni:
        snis.append(args.sni.strip())
    for path in args.sni_list or []:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    snis.append(line)
    seen, out = set(), []
    for s in snis:
        if s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    return out


def _parse_ports(raw: str) -> list[int]:
    ports: list[int] = []
    for part in str(raw).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError:
            continue
        if 0 < port < 65536 and port not in ports:
            ports.append(port)
    return ports or list(DEFAULT_PORTS)


# ══════════════════════════════════════════════════════════════
# 交互菜单
# ══════════════════════════════════════════════════════════════

async def menu_mode(args) -> int:
    print("\n╔══════════════════════════════════════════╗")
    print("║   REALITY-CF 节点发现  v2.0              ║")
    print("╚══════════════════════════════════════════╝\n")

    print("📌 选择目标 SNI：")
    for i, (sni, desc) in enumerate(PRESETS, 1):
        print(f"  {i}. {sni} ({desc})")
    print("  c. 自定义输入")
    choice = _ask("  选择 [1]: ", "1")

    if choice.isdigit() and 1 <= int(choice) <= len(PRESETS):
        sni = PRESETS[int(choice) - 1][0]
    else:
        sni = _ask("  输入 SNI: ", "")
        if not sni:
            print("未输入 SNI，退出")
            return 2

    cf_domain = _ask(f"\n📌 你的 CF 域名（用于 Step 2 验证）[{CF_PROBE_DOMAIN}]: ", CF_PROBE_DOMAIN)

    src = _ask("\n📌 目标来源  [1] IP 清单文件  [2] CT 日志  [3] TLS 账本目录  [1]: ", "1")
    targets: set[tuple[str, int]] = set()
    ports = list(DEFAULT_PORTS)

    if src == "2":
        from fetcher import fetch_ct_logs

        print("  抓取 CT 日志中...")
        targets |= await fetch_ct_logs(sni, ports, args.timeout, retries=args.ct_retries)
    elif src == "3":
        ledger = _ask("  账本目录: ", "")
        if ledger:
            targets |= await fetch_tls_ledger(ledger, sni, assume_port=args.assume_port)
    else:
        path = _ask("  IP 清单路径（每行 ip 或 ip:port）: ", "")
        if path:
            try:
                targets |= set(parse_targets_file(path, default_port=443))
            except Exception as exc:
                print(f"  读取失败: {exc}")
                return 2

    if not targets:
        print(_empty_hint(), file=sys.stderr)
        return 2

    cc = _ask(f"\n📌 并发 [{args.concurrency}]: ", str(args.concurrency))
    try:
        args.concurrency = max(1, int(cc))
    except ValueError:
        pass

    print(f"\n▶ 验证 {len(targets)} 个目标（并发 {args.concurrency}）\n")
    reset_stats()
    reporter = Reporter(args.output, fmt=args.format)
    reporter.start()
    async for result in verify_batch(
        sorted(targets), [sni], cf_domain,
        concurrency=args.concurrency, timeout=args.timeout,
        redundancy_check=not args.no_redundancy,
    ):
        reporter.on_result(result)
    reporter.finish()
    print_summary(get_stats().dump())
    return 0


def _ask(prompt: str, default: str) -> str:
    try:
        val = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return val or default


# ══════════════════════════════════════════════════════════════
# 入口
# ══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reality-cf",
        description="REALITY-CF 节点发现：CT 日志 / TLS 账本 / 自备清单 + 双重 TLS 验证",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--sni", help="目标大厂 SNI，如 images.apple.com")
    p.add_argument("--sni-list", action="append", metavar="FILE",
                   help="SNI 列表文件（一行一个），可重复")
    p.add_argument("--cf-domain", default=CF_PROBE_DOMAIN,
                   help=f"Step 2 使用的 Cloudflare 域名（默认 {CF_PROBE_DOMAIN}）")
    p.add_argument("--targets", action="append", metavar="FILE",
                   help="自备目标清单（一行 ip 或 ip:port），可重复")

    p.add_argument("--ledger", help="TLS 账本目录")
    p.add_argument("--ledger-cache", default="./scans", help="账本缓存目录（默认 ./scans）")
    p.add_argument("--ledger-limit", type=int, default=1, help="自动下载最新 N 个账本文件（默认 1）")
    p.add_argument("--auto-ledger", action=argparse.BooleanOptionalAction, default=False,
                   help="自动下载 TLS 账本（需要 SONAR_API_KEY）")
    p.add_argument("--no-ct", action="store_true", help="跳过 CT 日志阶段")
    p.add_argument("--no-ledger", action="store_true", help="跳过 TLS 账本阶段")
    p.add_argument("--assume-port", type=int, help="账本里没有端口信息时假定的端口")

    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help=f"端口嗅探列表（默认 {','.join(map(str, DEFAULT_PORTS))}）")
    p.add_argument("--concurrency", type=int, default=500, help="验证并发（默认 500）")
    p.add_argument("--timeout", type=float, default=3.0, help="单次握手超时秒（默认 3.0）")
    p.add_argument("--ct-retries", type=int, default=3, help="crt.sh 重试次数（默认 3）")
    p.add_argument("--output", default="vuln_reality_cf_report.json", help="输出文件")
    p.add_argument("--format", choices=("json", "jsonl"), default="json", help="输出格式")
    p.add_argument("--no-redundancy", action="store_true", help="关闭反蜜罐检测（不建议）")
    return p


async def amain() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.sni and not args.sni_list:
        if len(sys.argv) == 1:
            return await menu_mode(args)
        parser.error("需要 --sni 或 --sni-list（无参数运行进入交互菜单）")

    return await run(args)


def main() -> None:
    try:
        sys.exit(asyncio.run(amain()))
    except KeyboardInterrupt:
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
