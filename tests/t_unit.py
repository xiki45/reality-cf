"""
单元测试：不依赖网络、不依赖端口。

覆盖 v2 修复的每个判定点：
  - 主机名匹配（SAN 优先 / 通配符 RFC 6125 / CN 回退）
  - HTTP 头解析与 CF 特征判定
  - 目标清单解析
  - 账本端口推断（记录 port / 文件名 / manifest / assume_port）
  - Reporter 的 JSON、JSONL 与原子落盘
"""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import fetcher
import reporter as rep_mod
import verifier as V

PASS, FAIL = [], []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  {detail}" if detail else ""))


def _der(name: str) -> bytes:
    pem = (ROOT / "tests" / "certs" / name).read_bytes()
    cert = x509.load_pem_x509_certificate(pem)
    return cert.public_bytes(serialization.Encoding.DER)


def test_dnsname_match() -> None:
    print("\n[1] RFC 6125 主机名匹配")
    cases = [
        ("images.apple.com", "images.apple.com", True),
        ("IMAGES.APPLE.COM", "images.apple.com", True),
        ("images.apple.com.", "images.apple.com", True),
        ("*.apple.com", "images.apple.com", True),
        ("*.apple.com", "apple.com", False),          # 通配符不匹配裸域
        ("*.apple.com", "a.b.apple.com", False),      # 只匹配一级
        ("*.apple.com", "apple.com.evil.io", False),
        ("images.apple.com", "www.apple.com", False),
    ]
    for pat, host, want in cases:
        got = V._dnsname_match(pat, host)
        check(f"{pat!r} vs {host!r} = {got}", got is want)


def test_cert_match() -> None:
    print("\n[2] 证书匹配（SAN 优先，CN 回退）")
    apple = _der("cert.pem")
    wrong = _der("wrong.pem")

    ok, name, src = V.cert_match(apple, "images.apple.com")
    check("SAN 精确命中", ok and name == "images.apple.com" and src == "SAN", f"{name}/{src}")

    ok, name, src = V.cert_match(apple, "swdist.apple.com")
    check("SAN 通配符命中 *.apple.com", ok and name == "*.apple.com", f"{name}")

    ok, name, src = V.cert_match(apple, "apple.com")
    check("通配符不匹配裸域 → 拒绝", not ok, f"{name}")

    ok, _, src = V.cert_match(wrong, "images.apple.com")
    check("证书不匹配 → 拒绝", not ok, src)

    ok, name, src = V.cert_match(wrong, "www.example.com")
    check("另一张证书按 SAN 命中", ok and name == "www.example.com", f"{name}")


def test_http_parse() -> None:
    print("\n[3] HTTP 头解析与 CF 特征判定")
    raw = (
        b"HTTP/1.1 403 Forbidden\r\nServer: cloudflare\r\nCF-RAY: abc123-HKG\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    status, headers, _ = V._parse_head(raw)
    check("状态行解析", status == "HTTP/1.1 403 Forbidden", status)
    check("头字段小写归一", headers.get("cf-ray") == "abc123-HKG")
    check("CF 特征判定（cf-ray）", V._is_cf(headers) is True)

    raw2 = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
    _, h2, _ = V._parse_head(raw2)
    check("非 CF 站不误判", V._is_cf(h2) is False)

    _, h3, _ = V._parse_head(b"HTTP/1.1 200 OK\r\nServer: CloudFlare\r\n\r\n")
    check("server 头大小写无关", V._is_cf(h3) is True)


def test_targets_file() -> None:
    print("\n[4] 目标清单解析（含 host:port:sni 三列）")
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "targets.txt"
    p.write_text(
        "# 注释\n"
        "1.2.3.4:8443\n"
        "5.6.7.8\n"
        "\n"
        "9.9.9.9:abc\n"
        "1.2.3.4:8443\n"
        "host.example.com:443\n"
        "7.7.7.7:443:images.apple.com\n"
        "[2001:db8::1]:8443:example.com\n"
        "7.7.7.7:443:images.apple.com\n"
    )
    got = fetcher.parse_targets_file(str(p))
    check("注释/空行跳过 + 端口非法行跳过", ("9.9.9.9", 443, "") not in got and len(got) == 5, str(got))
    check("默认端口补齐", ("5.6.7.8", 443, "") in got)
    check("重复项去重", got.count(("1.2.3.4", 8443, "")) == 1)
    check("host:port 保留", ("host.example.com", 443, "") in got)
    check("host:port:sni 三列解析", ("7.7.7.7", 443, "images.apple.com") in got, str(got))
    check("IPv6 字面量 + sni", ("2001:db8::1", 8443, "example.com") in got, str(got))
    check("同 ip:port 不同 sni 不合并",
          len([t for t in got if t[0] == "7.7.7.7"]) == 1)


def test_links_file() -> None:
    print("\n[4b] vless:// 链接解析（不盲扫入口）")
    tmp = Path(tempfile.mkdtemp())
    p = tmp / "links.txt"
    p.write_text(
        "vless://uuid-1@1.2.3.4:443?security=reality&sni=www.cloudflare.com"
        "&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&type=tcp#N1\n"
        "vless://uuid-2@host.example.com:8443?security=tls&sni=x.com&pbk=K\n"
        "vless://uuid-3@5.6.7.8:443?security=reality&sni=a.com\n"
        "vless://uuid-4@1.2.3.4:443?security=reality&sni=www.cloudflare.com"
        "&pbk=PUBKEY&sid=ab12#DUP\n"
    )
    got = fetcher.parse_links_file(str(p))
    check("只收 security=reality", len(got) == 1, str(len(got)))
    n = got[0]
    check("补齐 host/port/sni", (n["host"], n["port"], n["sni"]) == ("1.2.3.4", 443, "www.cloudflare.com"))
    check("取到 REALITY 凭证", (n["uuid"], n["pbk"], n["sid"]) == ("uuid-1", "PUBKEY", "ab12"))
    check("flow 保留", n["flow"] == "xtls-rprx-vision")
    check("缺 pbk 的条目被丢弃", all(x["pbk"] for x in got))


def test_auth_classify() -> None:
    print("\n[4c] 认证失败原因归类")
    sys.path.insert(0, str(ROOT))
    from authcheck import _classify

    check("204 → 可用", _classify("", "204") == "")
    check("REALITY 认证失败", _classify(
        'error: connect error: REALITY authentication failed', "000") == "auth_failed")
    check("收到真证书 → 不是 REALITY", _classify(
        'REALITY: received real certificate (potential MITM or redirection)', "000") == "not_reality")
    check("超时", _classify("connect error: context deadline exceeded", "000") == "timeout")
    check("EOF", _classify("connect error: EOF", "000") == "eof")


def test_ranges_and_cache() -> None:
    print("\n[4d] 网段展开与认证缓存")
    from targets import parse_ranges_file
    from authcache import AuthCache, fingerprint

    tmp = Path(tempfile.mkdtemp())
    rp = tmp / "ranges.txt"
    rp.write_text("# dmit 洛圣都\n192.0.2.0/30\n198.51.100.7\n")
    got = parse_ranges_file(str(rp), [443])
    check("CIDR 展开为主机地址", [t[0] for t in got] == ["192.0.2.1", "192.0.2.2", "198.51.100.7"], str(got))
    check("端口套用到每条", all(t[1] == 443 for t in got))
    try:
        parse_ranges_file(str(rp), [443], max_hosts=2)
        check("超上限报错（防误扫 /8）", False)
    except ValueError:
        check("超上限报错（防误扫 /8）", True)

    n1 = {"uuid": "u1", "pbk": "k1", "sid": "s1", "host": "1.1.1.1", "port": 443}
    n2 = {"uuid": "u1", "pbk": "k1", "sid": "s1", "host": "2.2.2.2", "port": 8443}
    n3 = {"uuid": "u2", "pbk": "k1", "sid": "s1"}
    check("同凭证不同入口 → 指纹相同", fingerprint(n1) == fingerprint(n2))
    check("凭证变化 → 指纹不同", fingerprint(n1) != fingerprint(n3))

    cp = tmp / "cache.json"
    c = AuthCache(str(cp), ttl=3600)
    check("未命中返回 None", c.get(fingerprint(n1)) is None)
    c.put(fingerprint(n1), {"usable": False, "auth_error": "auth_failed"})
    c.save()
    c2 = AuthCache(str(cp), ttl=3600)
    hit = c2.get(fingerprint(n1))
    check("落盘后可复用", hit is not None and hit["auth_error"] == "auth_failed", str(hit))
    c2._data[fingerprint(n1)]["ts"] -= 7200          # 人为把时间戳拨回 2 小时
    check("TTL 过期失效", c2.get(fingerprint(n1)) is None)
    check("ttl<=0 视为不过期",
          AuthCache(str(cp), ttl=0).get(fingerprint(n1)) is not None)


def test_relay_state() -> None:
    print("\n[4e] 存活状态库（保鲜 + 轮换监控）")
    from relays import RelayState

    tmp = Path(tempfile.mkdtemp())
    st = RelayState(str(tmp / "s.json"))
    st.hit("1.1.1.1", 443, "a.example", "abc-LAX", ["x.com"])
    st.hit("1.1.1.1", 443, "a.example", "def-LAX")
    st.hit("2.2.2.2", 443, "b.example", "ghi-SIN")
    rec = st.data["1.1.1.1:443"]
    check("命中累计轮数", rec["alive_rounds"] == 2, str(rec["alive_rounds"]))
    check("记录 colo", rec.get("colo") == "LAX", str(rec.get("colo")))

    st.miss("2.2.2.2", 443, ["apple.com"])
    check("未命中把 miss_rounds 加一", st.data["2.2.2.2:443"]["miss_rounds"] == 1)
    check("未命中记录 dest 证书名", "apple.com" in st.data["2.2.2.2:443"]["dest_current"])

    st.miss("1.1.1.1", 443, ["tesla.com"])
    check("dest 变化进入 history", len(st.data["1.1.1.1:443"]["dest_history"]) == 2,
          str(st.data["1.1.1.1:443"]["dest_history"]))
    check("dest 重复不重复记", (st.miss("1.1.1.1", 443, ["tesla.com"]),
                              len(st.data["1.1.1.1:443"]["dest_history"]))[1] == 2)

    st.save()
    st2 = RelayState(str(tmp / "s.json"))
    check("状态可落盘复用", len(st2) == 2, str(len(st2)))

    st2.hit("3.3.3.3", 443, "c.example")
    active = st2.active(min_alive_rounds=1)
    check("当前有效 = 未连续 miss 的", all(r["miss_rounds"] == 0 for r in active), str(len(active)))
    stable = st2.active(min_alive_rounds=2)
    check("按累计成立轮数过滤", [r["ip"] for r in stable] == [], str([r["ip"] for r in stable]))
    n = st2.export(str(tmp / "live.txt"), min_alive_rounds=1)
    check("导出清单行数", n == len(active) and (tmp / "live.txt").exists(), str(n))
    check("轮换机器可识别", len(st2.rotating()) == 1, str(len(st2.rotating())))


def test_cert_names() -> None:
    print("\n[4f] 证书名提取（dest 监控）")
    sys.path.insert(0, str(ROOT))
    from verifier import cert_names

    check("空输入返回空", cert_names(None) == [])
    check("脏数据不抛异常", cert_names(b"\x00\x01garbage") == [])


def test_ledger_ports() -> None:
    print("\n[5] 账本端口推断四路兜底")
    tmp = Path(tempfile.mkdtemp())
    sni = "images.apple.com"

    with gzip.open(tmp / "port-443-tls.json.gz", "wt") as f:
        f.write(json.dumps({"ip": "10.0.0.1", "server_name": sni}) + "\n")

    # Sonar 真实命名：端口只能从记录里拿
    with gzip.open(tmp / "2018-06-15-1529049662-certs.json.gz", "wt") as f:
        f.write(json.dumps({"ip": "10.0.0.2", "port": 8443, "server_name": sni}) + "\n")

    # 无端口信息：应走 assume_port=2053
    with gzip.open(tmp / "noports.json.gz", "wt") as f:
        f.write(json.dumps({"ip": "10.0.0.3", "server_name": sni}) + "\n")

    # 无端口信息但有 manifest
    with gzip.open(tmp / "named.json.gz", "wt") as f:
        f.write(json.dumps({"ip": "10.0.0.4", "server_name": sni}) + "\n")
    (tmp / "manifest.json").write_text(json.dumps({"files": {"named.json.gz": 2083}}))

    # 不该命中的行
    with gzip.open(tmp / "other.json.gz", "wt") as f:
        f.write(json.dumps({"ip": "10.0.0.5", "server_name": "other.example"}) + "\n")

    import asyncio
    got = asyncio.run(fetcher.fetch_tls_ledger(str(tmp), sni, assume_port=2053))
    expect = {
        ("10.0.0.1", 443),     # 文件名
        ("10.0.0.2", 8443),    # 记录字段
        ("10.0.0.3", 2053),    # assume_port
        ("10.0.0.4", 2083),    # manifest
    }
    check("四种端口来源全部命中", got == expect, f"got={sorted(got)}")
    check("无关 SNI 不误收", ("10.0.0.5", 443) not in got)


def test_reporter() -> None:
    print("\n[6] Reporter 落盘")
    tmp = Path(tempfile.mkdtemp())
    row = {"ip": "1.2.3.4", "port": 443, "target_sni": "images.apple.com",
           "status": "AVAILABLE", "common_name": "images.apple.com"}

    for fmt, path in (("json", tmp / "a.json"), ("jsonl", tmp / "b.jsonl")):
        rp = rep_mod.Reporter(str(path), fmt=fmt)
        rp.start()
        rp.on_result(dict(row))
        rp.on_result(dict(row, ip="5.6.7.8"))
        n = rp.finish()
        check(f"{fmt} 计数", n == 2, str(n))
        check(f"{fmt} 无 .part 残留", not list(tmp.glob("*.part")))

    data = json.loads((tmp / "a.json").read_text())
    check("json 数组合法且带 geo/timestamp", len(data) == 2 and "geo" in data[0] and "timestamp" in data[0])

    lines = [json.loads(x) for x in (tmp / "b.jsonl").read_text().strip().split("\n")]
    check("jsonl 每行一个对象", len(lines) == 2 and lines[1]["ip"] == "5.6.7.8")

    rp = rep_mod.Reporter(str(tmp / "empty.json"))
    rp.start(); rp.finish()
    check("0 命中输出合法 JSON", json.loads((tmp / "empty.json").read_text()) == [])


def main() -> int:
    test_dnsname_match()
    test_cert_match()
    test_http_parse()
    test_targets_file()
    test_ranges_and_cache()
    test_relay_state()
    test_cert_names()
    test_links_file()
    test_auth_classify()
    test_ledger_ports()
    test_reporter()

    print(f"\n{'='*54}")
    print(f"单元测试: {len(PASS)} 通过 / {len(FAIL)} 失败")
    if FAIL:
        print("失败项: " + ", ".join(FAIL))
    print("=" * 54)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    sys.exit(main())
