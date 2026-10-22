"""
持续复测（保鲜）与 dest 轮换监控

单次快照没有意义：实测同一批 DMIT 机器 50 分钟内从 540 台掉到 2 台，
因为机场会定时把 REALITY 的 dest 从 Cloudflare 换走。

所以本项目的主循环是「反复扫、记录存活轮数、导出当前有效清单」：

    python main.py --ranges dmit.txt --ports 443 --sni www.cloudflare.com \
        --recheck-interval 600 --rounds 6 --export live.txt

每一轮：
  1. 用本轮目标跑一遍三步验证（TLS 层命中即算「当前可白嫖」）
  2. 命中的写入状态库（alive_rounds +1），未命中的记录 miss 与对端证书名
  3. 立刻导出当前有效清单，方便边跑边用
  4. 睡 `--recheck-interval` 秒后进入下一轮

dest 轮换监控：miss 时把对端证书里的域名记进 dest_history。
history 变长的那些机器，就是「dest 会周期性变化」的候选 —— 它们很可能
在某几轮里把 dest 指回 Cloudflare，是值得长期盯的目标。
"""

from __future__ import annotations

import asyncio
import logging
import time

from relays import RelayState
from reporter import Reporter, print_summary
from verifier import get_stats, reset_stats, verify_batch

logger = logging.getLogger("reality-cf.monitor")

__all__ = ["run_monitor"]


async def run_monitor(args, collect) -> int:
    """collect(args, snis, ports) -> (targets, nodes)；由 main 传入以复用取数逻辑。"""
    import verifier as _v

    snis = _load_snis_local(args)
    ports = _parse_ports_local(args)
    targets, _nodes = await collect(args, snis, ports)
    if not targets:
        logger.error("没有任何目标，监控无法启动")
        return 2

    state = RelayState(getattr(args, "state", "relay_state.json"))
    rounds = max(1, int(getattr(args, "rounds", 1) or 1))
    interval = float(getattr(args, "recheck_interval", 0) or 0)
    min_alive = max(1, int(getattr(args, "active_rounds", 1) or 1))

    logger.info("监控启动：%d 个目标 | %d 轮 | 间隔 %.0fs | 状态文件 %s",
                len(targets), rounds, interval, state.path)

    total_hits = 0
    try:
        for rnd in range(1, rounds + 1):
            logger.info("── 第 %d/%d 轮 ──", rnd, rounds)
            reset_stats()
            reporter = Reporter(args.output, fmt=args.format)
            reporter.start()
            seen: set[tuple[str, str, int]] = set()

            def on_miss(ip: str, port: int, names: list[str]) -> None:
                # 只记「曾经是命中」的机器，否则状态库会被几万个无关 IP 撑爆
                if f"{ip}:{port}" in state.data:
                    state.miss(ip, port, names)

            _v.MISS_HOOK = on_miss
            try:
                async for result in verify_batch(
                    sorted(targets), snis, args.cf_domain,
                    concurrency=args.concurrency,
                    timeout=args.timeout,
                    redundancy_check=not args.no_redundancy,
                ):
                    if not result:
                        continue
                    key = (result["ip"], result["port"], 0)
                    if key in seen:
                        continue
                    seen.add(key)
                    state.hit(result["ip"], result["port"], result.get("target_sni"),
                              (result.get("evidence") or {}).get("cf_ray"))
                    reporter.on_result(result)
            finally:
                _v.MISS_HOOK = None

            reporter.finish()
            total_hits += reporter.count
            state.save()

            active = state.active(min_alive_rounds=1)
            stable = state.active(min_alive_rounds=min_alive)
            exported = state.export(
                getattr(args, "export", "live_relays.txt"),
                active_only=True, min_alive_rounds=min_alive,
                with_sni=getattr(args, "export_sni", None),
            )
            logger.info("轮次完成：本轮命中 %d | 状态库 %d | 当前有效 %d | 稳定(>=%d轮) %d → %s",
                        len(seen), len(state), len(active), min_alive, len(stable),
                        getattr(args, "export", "live_relays.txt"))

            st = get_stats().dump()
            print_summary(st)
            if rnd < rounds:
                logger.info("休眠 %.0fs 后进入下一轮（Ctrl-C 中止，已命中结果已落盘）", interval)
                await asyncio.sleep(interval)
    except KeyboardInterrupt:
        logger.warning("已中断，状态已保存")
    finally:
        state.save()

    rotating = state.rotating()
    if rotating:
        logger.info("dest 发生过轮换的机器 %d 台（值得长期盯）：", len(rotating))
        for r in rotating[:8]:
            hist = " → ".join("/".join(h["names"][:2]) for h in r["dest_history"][-3:])
            logger.info("  %s:%d  %s", r["ip"], r["port"], hist)
    logger.info("监控结束：共 %d 轮，累计命中 %d 次", rounds, total_hits)
    return 0


# main.py 里有同名实现，这里做局部导入避免循环依赖
def _load_snis_local(args):
    import main as _m
    return _m._load_snis(args)


def _parse_ports_local(args):
    import main as _m
    return _m._parse_ports(args.ports)
