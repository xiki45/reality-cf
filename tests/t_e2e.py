"""
端到端：起本地多场景 mock 服务，跑真实的 verify_single / verify_batch。

断言每个场景的判定结果与统计计数器，确保：
  - 正确节点能命中（且 confidence=high）
  - 蜜罐被反蜜罐探针拦下
  - 普通 TLS / 非 CF 后端 / 证书不符 / 直接拒连 分别落到对应丢弃原因
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import mock_server
import verifier as V

CF = mock_server.CF_DOMAIN
SNI = "images.apple.com"
P = mock_server.DEFAULT_PORTS

PASS, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


async def main() -> int:
    servers = await mock_server.start()
    try:
        print("\n[1] 正样本：SNI 白名单 + CF 后端 → 应命中")
        V.reset_stats()
        r = await V.verify_single("127.0.0.1", P["cf_sni_filtered"], SNI, CF, timeout=2.0)
        check("命中", r is not None, str(r))
        if r:
            check("confidence=high（有 cf-ray）", r["confidence"] == "high", r["confidence"])
            check("证据含 cf_ray", bool((r.get("evidence") or {}).get("cf_ray")))
            check("matched_by=SAN", r["matched_by"] == "SAN", r["matched_by"])
        check("统计 hit=1", V.get_stats().hit == 1, str(V.get_stats().hit))

        print("\n[2] 蜜罐：任意 SNI 都回 CF 头 → 反蜜罐应拦下")
        V.reset_stats()
        r = await V.verify_single("127.0.0.1", P["cf_any_sni"], SNI, CF, timeout=2.0)
        check("被丢弃", r is None, str(r))
        check("统计 honeypot=1", V.get_stats().honeypot == 1, str(V.get_stats().honeypot))

        print("\n[3] 同一蜜罐关闭反蜜罐 → 会命中（证明差异确实来自探针）")
        V.reset_stats()
        r = await V.verify_single("127.0.0.1", P["cf_any_sni"], SNI, CF,
                                  timeout=2.0, redundancy_check=False)
        check("命中", r is not None)

        print("\n[4] 负样本分类")
        cases = [
            ("plain_tls", "no_cf"),
            ("non_cf_target", "no_cf"),
            ("wrong_cert", "name_mismatch"),
        ]
        for scenario, expect_counter in cases:
            V.reset_stats()
            r = await V.verify_single("127.0.0.1", P[scenario], SNI, CF, timeout=2.0)
            stats = V.get_stats()
            check(f"{scenario} → 丢弃", r is None, str(r))
            check(f"{scenario} → {expect_counter}=1",
                  getattr(stats, expect_counter) == 1,
                  f"{expect_counter}={getattr(stats, expect_counter)}")

        # 未监听端口
        V.reset_stats()
        r = await V.verify_single("127.0.0.1", 18999, SNI, CF, timeout=1.0)
        check("未监听端口 → probe_fail=1", r is None and V.get_stats().probe_fail == 1)

        print("\n[5] verify_batch：真流式 + 并发 + 结果正确")
        V.reset_stats()
        targets = [
            ("127.0.0.1", P["cf_sni_filtered"]),
            ("127.0.0.1", P["plain_tls"]),
            ("127.0.0.1", P["cf_any_sni"]),
            ("127.0.0.1", P["wrong_cert"]),
            ("127.0.0.1", P["tarpit"]),          # 会卡到超时，用来验证「不等全部完成」
        ]
        t0 = time.monotonic()
        arrivals, results = [], []
        async for res in V.verify_batch(targets, [SNI], CF, concurrency=4,
                                        timeout=2.0, redundancy_check=True):
            arrivals.append(time.monotonic() - t0)
            results.append(res)
        total = time.monotonic() - t0
        check("只命中 1 个", len(results) == 1, f"{[r['port'] for r in results]}")
        check("命中端口正确", results and results[0]["port"] == P["cf_sni_filtered"])
        check("流式：首条早于结束", arrivals and arrivals[0] < total, f"{arrivals} vs {total:.2f}s")
        check("统计总数=5", V.get_stats().total == 5, str(V.get_stats().total))
        check("慢目标确实拖长了总时长（>1s）", total > 1.0, f"{total:.2f}s")
        check("首条远早于结束", arrivals[0] < total / 2, f"首条 {arrivals[0]:.3f}s / 总计 {total:.2f}s")

        print("\n[6] 空 SNI 列表直接返回，不报错")
        n = 0
        async for _ in V.verify_batch([("127.0.0.1", 18999)], [], CF):
            n += 1
        check("无异常且无结果", n == 0)

        print("\n[7] 单目标异常不影响整批")
        V.reset_stats()
        got = []
        async for r in V.verify_batch(
            [("127.0.0.1", P["cf_sni_filtered"]), ("not-a-host", 443),
             ("127.0.0.1", P["cf_sni_filtered"])],
            [SNI], CF, concurrency=3, timeout=1.0,
        ):
            got.append(r)
        check("坏目标被跳过、其余照常命中", len(got) == 2, str(len(got)))
    finally:
        for s in servers.values():
            s.close()
        await asyncio.gather(*[s.wait_closed() for s in servers.values()], return_exceptions=True)

    print(f"\n{'='*54}")
    print(f"端到端: {len(PASS)} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
    print("=" * 54)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
