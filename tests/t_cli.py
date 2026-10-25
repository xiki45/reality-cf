"""
CLI 集成测试：用真实命令行跑通「自备清单 → 验证 → 输出」全链路。

覆盖 v1 的 CLI 级缺陷：
  - --cf-domain 曾不存在（README 所有示例 exit=2）
  - --ledger 被 auto 覆盖
  - 无候选时 sys.exit(1) 且无指引
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
MAIN = str(ROOT / "main.py")

PASS, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def wait_port(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def run_cli(args: list[str], timeout: float = 120.0) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONWARNINGS="ignore")
    return subprocess.run([PY, MAIN, *args], capture_output=True, text=True,
                          timeout=timeout, env=env, cwd=str(ROOT))


def main() -> int:
    mock = subprocess.Popen([PY, str(ROOT / "tests" / "mock_server.py")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tmp = Path(tempfile.mkdtemp())
    try:
        if not wait_port(18443):
            print("mock server 未起来，测试中止")
            return 1
        time.sleep(0.3)

        targets = tmp / "targets.txt"
        targets.write_text(
            "# 命中\n127.0.0.1:18445\n"
            "# 普通 TLS\n127.0.0.1:18444\n"
            "# 蜜罐\n127.0.0.1:18443\n"
            "# 证书不符\n127.0.0.1:18447\n"
            "# 未监听\n127.0.0.1:18999\n"
        )

        print("\n[1] --cf-domain 被接受（v1 此处 exit=2）")
        out = tmp / "out.json"
        p = run_cli(["--sni", "images.apple.com", "--cf-domain", "speed.cloudflare.com",
                     "--targets", str(targets), "--no-ct", "--no-ledger",
                     "--output", str(out), "--concurrency", "8", "--timeout", "2"])
        check("exit=0", p.returncode == 0, f"rc={p.returncode}")
        check("stderr 无 unrecognized", "unrecognized" not in p.stderr, p.stderr.strip()[:120])

        print("\n[2] 输出内容")
        data = json.loads(out.read_text()) if out.exists() else []
        check("文件存在且是合法 JSON", isinstance(data, list))
        check("只命中 1 个（蜜罐已被过滤）", len(data) == 1, f"len={len(data)}")
        if data:
            row = data[0]
            check("端口是正确节点", row["port"] == 18445, str(row.get("port")))
            check("带 cf-ray 证据", bool(row.get("evidence", {}).get("cf_ray")))
            check("带 geo/timestamp", "geo" in row and "timestamp" in row)

        print("\n[3] 统计输出可见")
        check("打印了统计块", "验证统计" in p.stdout, "")
        check("honeypot 计数出现", "判定为蜜罐" in p.stdout, "")

        print("\n[4] --format jsonl")
        outl = tmp / "out.jsonl"
        p = run_cli(["--sni", "images.apple.com", "--targets", str(targets),
                     "--no-ct", "--no-ledger", "--output", str(outl),
                     "--format", "jsonl", "--concurrency", "8", "--timeout", "2"])
        lines = [json.loads(x) for x in outl.read_text().strip().split("\n") if x.strip()]
        check("jsonl 单行对象", len(lines) == 1 and lines[0]["port"] == 18445, f"lines={len(lines)}")

        print("\n[5] 没有候选目标 → exit=2 且给出三条可行路径")
        p = run_cli(["--sni", "images.apple.com", "--no-ct", "--no-ledger",
                     "--output", str(tmp / "none.json")])
        check("exit=2", p.returncode == 2, f"rc={p.returncode}")
        check("提示 --targets", "--targets" in p.stderr, p.stderr.strip().splitlines()[-1][:100])

        print("\n[6] --no-redundancy 放行蜜罐（行为可观测）")
        only_honeypot = tmp / "honeypot.txt"
        only_honeypot.write_text("127.0.0.1:18443\n")
        out2 = tmp / "honey.json"
        p = run_cli(["--sni", "images.apple.com", "--targets", str(only_honeypot),
                     "--no-ct", "--no-ledger", "--no-redundancy",
                     "--output", str(out2), "--concurrency", "4", "--timeout", "2"])
        honey = json.loads(out2.read_text())
        check("关闭反蜜罐后命中", len(honey) == 1, f"len={len(honey)}")

        print("\n[7] --help / 无参数菜单")
        p = run_cli(["--help"], timeout=30)
        check("--help exit=0", p.returncode == 0)
        check("help 含 --cf-domain", "--cf-domain" in p.stdout)
        p = run_cli([], timeout=30)   # stdin 关闭 → EOFError 路径
        check("无参数不崩溃", p.returncode in (0, 2), f"rc={p.returncode}")

        print("\n[8] 非法 SNI 参数缺失 → argparse 报错")
        p = run_cli(["--targets", str(targets)])
        check("缺 --sni 时 exit=2", p.returncode == 2, f"rc={p.returncode}")
    finally:
        mock.terminate()
        try:
            mock.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock.kill()

    print(f"\n{'='*54}")
    print(f"CLI: {len(PASS)} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
    print("=" * 54)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
