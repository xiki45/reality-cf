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
import os
import sys

from fetcher import (
    DEFAULT_PORTS, fetch_ct_logs, fetch_tls_ledger, parse_links_file,
    parse_ranges_file, parse_targets_file,
)
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

async def collect_targets(args, snis: list[str], ports: list[int]):
    """
    返回 (targets, nodes)。

    targets 里每项是 (host, port, sni)：sni 非空表示「只用它自己的 SNI 配对」
    （不盲扫）；为空表示「跟全局 --sni/--sni-list 逐一配对」。
    nodes 是 vless:// 链接解析出的完整凭证，供 --verify-auth 使用。
    """
    targets: set[tuple[str, int, str]] = set()
    nodes: dict[tuple[str, int, str], dict] = {}

    # 0: 订阅分享链接（自带 SNI + REALITY 凭证）
    for path in args.links or []:
        try:
            got = parse_links_file(path)
        except FileNotFoundError:
            logger.error("链接文件不存在: %s", path)
            continue
        except Exception as exc:
            logger.error("链接文件解析失败 %s: %s", path, exc)
            continue
        for n in got:
            key = (n["host"], n["port"], n["sni"].lower())
            targets.add(key)
            nodes.setdefault(key, n)
        logger.info("[Phase 0] 订阅链接 %s → %d 个 REALITY 节点（自带 SNI）", path, len(got))

    # R: 网段清单（按机房扫：不需要凭证，也不需要订阅）
    for path in getattr(args, "ranges", None) or []:
        try:
            got = parse_ranges_file(path, ports, max_hosts=getattr(args, "range_max", 200000))
            logger.info("[Phase 0R] 网段清单 %s → %d 个 IP:PORT", path, len(got))
            targets.update(got)
        except FileNotFoundError:
            logger.error("网段清单不存在: %s", path)
        except Exception as exc:
            logger.error("网段清单解析失败 %s: %s", path, exc)

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
            targets.update((ip, port, "") for ip, port in got)

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
                targets.update((ip, port, "") for ip, port in got)
        elif args.ledger:
            logger.error("账本目录不可用: %s", args.ledger)

    return targets, nodes


def _empty_hint() -> str:
    return (
        "没有拿到任何候选目标。四条路任选其一：\n"
        "  0) 给订阅链接（首选，自带每节点 SNI）：reality-cf --links sub.txt --cf-domain <CF域名> --verify-auth\n"
        "  1) 给 IP 清单：reality-cf --targets ips.txt --cf-domain <你的CF域名>\n"
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
                ", ".join(snis) or "(仅用各目标自带 SNI)", args.cf_domain, ",".join(map(str, ports)))

    if args.rounds > 1 or args.recheck_interval > 0:
        from monitor import run_monitor

        return await run_monitor(args, collect_targets)

    targets, nodes = await collect_targets(args, snis, ports)
    if not targets:
        print(_empty_hint(), file=sys.stderr)
        return 2

    own_sni = sum(1 for t in targets if t[2])
    logger.info("总计 %d 个待验证目标（其中 %d 个自带 SNI）| 并发 %d | 超时 %.1fs",
                len(targets), own_sni, args.concurrency, args.timeout)

    reset_stats()
    reporter = Reporter(args.output, fmt=args.format)
    reporter.start()

    seen: set[tuple[str, int]] = set()
    dup = 0
    buffered: list[dict] = []

    async def handle(result: dict | None) -> None:
        nonlocal dup
        if not result:
            return
        key = (result["ip"], result["port"])
        if key in seen:
            dup += 1
            if not args.verify_auth:
                return
        seen.add(key)
        if args.verify_auth:
            buffered.append(result)
        else:
            reporter.on_result(result)

    try:
        async for result in verify_batch(
            sorted(targets), snis, args.cf_domain,
            concurrency=args.concurrency,
            timeout=args.timeout,
            redundancy_check=not args.no_redundancy,
        ):
            await handle(result)
    except KeyboardInterrupt:
        reporter.abort()
        logger.warning("已中断，已发现的结果已落盘 → %s", args.output)
        st = get_stats().dump()
        st["dup_hit"] = dup
        print_summary(st)
        return 130

    # ── Phase 4: 真实客户端认证复核（可选） ──
    auth_counts = None
    if args.verify_auth and buffered:
        auth_counts = await _run_auth_stage(args, buffered, nodes)
        for result in buffered:
            reporter.on_result(result)
        if auth_counts is not None:
            logger.info("认证复核：%d/%d 可用", auth_counts["usable"], len(buffered))
    elif args.verify_auth:
        logger.warning("--verify-auth 已开启但没有命中节点，跳过认证复核")

    reporter.finish()
    st = get_stats().dump()
    st["dup_hit"] = dup
    if args.verify_auth and buffered:
        st["auth"] = auth_counts
    print_summary(st)
    return 0 if reporter.count or get_stats().total else 1


async def _run_auth_stage(args, results: list[dict], nodes: dict):
    """
    用本机真实内核做 REALITY 认证复核。

    三重省时（本轮实测 319 个命中里有 268 个凭证失效，全是重复劳动）：
      1. 凭证指纹缓存（跨次运行）—— 同一套 uuid/pbk/sid 只实测一次
      2. 同轮兄弟节点短路      —— 本轮已测过同凭证，直接复用结论
      3. --min-usable 提前收工  —— 凑够目标数量就停，不扫完全部
    """
    import asyncio as _aio

    from authcache import AuthCache, fingerprint
    from authcheck import find_core, verify_node

    found = find_core(args.core)
    if not found:
        for r in results:
            r["usable"] = None
            r["auth_error"] = "no_core"
        logger.warning(
            "未找到可用的客户端内核，跳过认证复核。可显式指定："
            "--core '/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo'"
        )
        return None

    core, kind = found
    counts = {"usable": 0, "auth_failed": 0, "not_reality": 0, "timeout": 0,
              "other": 0, "cache": 0, "sibling": 0, "skipped": 0}
    cache = AuthCache(getattr(args, "auth_cache", None) or None,
                      ttl=int(getattr(args, "auth_cache_ttl", 6 * 3600) or 0))
    min_usable = int(getattr(args, "min_usable", 0) or 0)
    workers = max(1, int(getattr(args, "auth_concurrency", 4) or 1))

    todo: list[tuple[dict, dict, str]] = []
    seen_fp: dict[str, dict] = {}
    for r in results:
        key = (r["ip"], r["port"], str(r.get("target_sni", "")).lower())
        node = nodes.get(key)
        if not node:
            r["usable"] = None
            r["auth_error"] = "no_credentials"
            counts["other"] += 1
            continue
        fp = fingerprint(node)
        r["_fp"] = fp
        cached = cache.get(fp)
        if cached:
            r.update(usable=bool(cached.get("usable")),
                     auth_error=cached.get("auth_error") or "",
                     http_code="", core=os.path.basename(core), from_cache=True)
            counts["usable" if cached.get("usable") else
                   (cached.get("auth_error") if cached.get("auth_error") in counts else "other")] += 1
            counts["cache"] += 1
            continue
        if fp in seen_fp:
            prev = seen_fp[fp]
            r.update(usable=prev["usable"], auth_error=prev["auth_error"],
                     http_code=prev.get("http_code", ""), core=prev.get("core", ""),
                     from_sibling=True)
            counts["usable" if prev["usable"] else
                   (prev["auth_error"] if prev["auth_error"] in counts else "other")] += 1
            counts["sibling"] += 1
            continue
        todo.append((r, node, fp))

    logger.info("认证复核内核: %s (%s) | 待测 %d 个（缓存命中 %d，同凭证跳过 %d）| 并发 %d",
                core, kind, len(todo), counts["cache"], counts["sibling"], workers)
    lock = _aio.Lock()

    async def one(r: dict, node: dict, fp: str) -> bool:
        info = await _aio.to_thread(verify_node, core, kind, node, args.auth_timeout)
        r.update(info)
        r["_fp"] = fp
        async with lock:
            cache.put(fp, info)
            seen_fp[fp] = info
            if info["usable"]:
                counts["usable"] += 1
                logger.info("  ✅ %s:%s 认证通过", r["ip"], r["port"])
            else:
                err = info["auth_error"]
                counts[err if err in counts else "other"] += 1
                logger.info("  ❌ %s:%s %s", r["ip"], r["port"], err)
            return min_usable > 0 and counts["usable"] >= min_usable

    # 分批跑，每批结束检查是否已凑够 --min-usable
    for i in range(0, len(todo), workers):
        chunk = todo[i:i + workers]
        reached = await _aio.gather(*(one(r, n, fp) for r, n, fp in chunk))
        if any(reached):
            logger.info("已达 --min-usable %d，提前结束复核（跳过 %d 个）",
                        min_usable, len(todo) - i - len(chunk))
            for r, _n, _fp in todo[i + len(chunk):]:
                r["usable"] = None
                r["auth_error"] = "skipped_min_usable"
                counts["skipped"] += 1
            break

    cache.save()
    return counts


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
    targets: set[tuple[str, int, str]] = set()
    ports = list(DEFAULT_PORTS)

    if src == "2":
        from fetcher import fetch_ct_logs

        print("  抓取 CT 日志中...")
        targets |= {(ip, port, "") for ip, port in await fetch_ct_logs(
            sni, ports, args.timeout, retries=args.ct_retries)}
    elif src == "3":
        ledger = _ask("  账本目录: ", "")
        if ledger:
            targets |= {(ip, port, "") for ip, port in await fetch_tls_ledger(
                ledger, sni, assume_port=args.assume_port)}
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
        description=(
            "找出「当前会把未认证流量转发给 Cloudflare」的第三方机器（可借道的中转）。\n"
            "判定只用 TLS 三步验证，不需要任何 REALITY 凭证。\n"
            "\n"
            "典型用法：\n"
            "  reality-cf --ranges dmit.txt --ports 443 --sni www.cloudflare.com \\\n"
            "      --cf-domain www.cloudflare.com --rounds 6 --recheck-interval 600"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── 核心：判据 ──
    g0 = p.add_argument_group("判据（三步 TLS 验证）")
    g0.add_argument("--sni", help="目标 SNI；任选一个托管在 Cloudflare 的域名即可（不必是你的）")
    g0.add_argument("--sni-list", action="append", metavar="FILE",
                    help="SNI 列表文件（一行一个），可重复")
    g0.add_argument("--cf-domain", default=CF_PROBE_DOMAIN,
                    help=f"Step 2 的反代探针域名（默认 {CF_PROBE_DOMAIN}，可与 --sni 相同）")
    g0.add_argument("--no-redundancy", action="store_true",
                    help="关闭反蜜罐检测（不建议：对 .invalid 也回 CF 头的机器会看到你的明文）")

    # ── 核心：目标来源 ──
    g1 = p.add_argument_group("目标来源（任选其一或组合）")
    g1.add_argument("--ranges", action="append", metavar="FILE",
                    help="CIDR 网段清单（按机房扫，最有效），可重复")
    g1.add_argument("--range-max", type=int, default=200000,
                    help="网段展开后的目标数上限（默认 20 万，防误扫 /8）")
    g1.add_argument("--targets", action="append", metavar="FILE",
                    help="目标清单（一行 host / host:port / host:port:sni），可重复")
    g1.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help=f"端口列表（默认 {','.join(map(str, DEFAULT_PORTS))}；实测这类机器基本只开 443）")
    g1.add_argument("--ledger", help="TLS 账本目录")
    g1.add_argument("--ledger-cache", default="./scans", help="账本缓存目录（默认 ./scans）")
    g1.add_argument("--ledger-limit", type=int, default=1, help="自动下载最新 N 个账本文件（默认 1）")
    g1.add_argument("--auto-ledger", action=argparse.BooleanOptionalAction, default=False,
                    help="自动下载 TLS 账本（需要 SONAR_API_KEY）")
    g1.add_argument("--no-ct", action="store_true", help="跳过 CT 日志阶段")
    g1.add_argument("--no-ledger", action="store_true", help="跳过 TLS 账本阶段")
    g1.add_argument("--assume-port", type=int, help="账本里没有端口信息时假定的端口")

    # ── 保鲜与轮换监控 ──
    g2 = p.add_argument_group("保鲜与轮换监控（推荐工作模式）")
    g2.add_argument("--rounds", type=int, default=1, help="复测轮数（默认 1）")
    g2.add_argument("--recheck-interval", type=float, default=0,
                    help="轮次间隔秒；>0 即进入持续监控模式")
    g2.add_argument("--state", default="relay_state.json",
                    help="存活状态库（默认 relay_state.json）")
    g2.add_argument("--active-rounds", type=int, default=1,
                    help="导出时要求累计成立轮数（默认 1，调高更稳但更少）")
    g2.add_argument("--export", default="live_relays.txt",
                    help="当前有效中转清单输出路径（默认 live_relays.txt）")
    g2.add_argument("--export-sni", metavar="SNI",
                    help="导出时统一附带的 SNI（省略则用命中时用过的 SNI）")

    # ── 性能与输出 ──
    g3 = p.add_argument_group("性能与输出")
    g3.add_argument("--concurrency", type=int, default=500, help="并发（默认 500）")
    g3.add_argument("--timeout", type=float, default=3.0, help="单次握手超时秒（默认 3.0）")
    g3.add_argument("--ct-retries", type=int, default=3, help="crt.sh 重试次数（默认 3）")
    g3.add_argument("--output", default="vuln_reality_cf_report.json", help="输出文件")
    g3.add_argument("--format", choices=("json", "jsonl"), default="json", help="输出格式")

    # ── 附录：自用分支（与借道无关） ──
    g4 = p.add_argument_group(
        "附录 · 自用节点（默认关闭，与「借道中转」无关）",
        "这一组是为了「把节点当客户端登录」而做的：需要 REALITY 凭证可用。\n"
        "对寻找可借道的中转没有任何帮助 —— 命中判据只看 TLS 层，不看能不能登录。",
    )
    g4.add_argument("--links", action="append", metavar="FILE",
                    help="vless:// 分享链接文件（自带每节点 SNI 与凭证），可重复")
    g4.add_argument("--verify-auth", action="store_true",
                    help="对命中节点用本机内核跑 REALITY 握手，判定「凭证还能不能登录」")
    g4.add_argument("--core", metavar="PATH",
                    help="客户端内核路径（默认自动探测 Clash Party / Mihomo Party / xray）")
    g4.add_argument("--auth-timeout", type=float, default=9.0,
                    help="认证复核单节点超时秒（默认 9.0）")
    g4.add_argument("--auth-concurrency", type=int, default=4,
                    help="认证复核并发（每个并发起一个内核进程，默认 4）")
    g4.add_argument("--min-usable", type=int, default=0,
                    help="凑够 N 个认证可用就提前结束（0 = 不限）")
    g4.add_argument("--auth-cache", metavar="FILE", default="auth_cache.json",
                    help="认证结果缓存文件（默认 auth_cache.json，传空串关闭）")
    g4.add_argument("--auth-cache-ttl", type=int, default=6 * 3600,
                    help="缓存有效期秒（默认 6 小时，0 = 永不过期）")
    return p


async def amain() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.sni and not args.sni_list and not args.links:
        if len(sys.argv) == 1:
            return await menu_mode(args)
        parser.error("需要 --sni / --sni-list / --links 之一（无参数运行进入交互菜单）")

    return await run(args)


def main() -> None:
    try:
        sys.exit(asyncio.run(amain()))
    except KeyboardInterrupt:
        print()
        sys.exit(130)


if __name__ == "__main__":
    main()
