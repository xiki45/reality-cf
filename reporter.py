"""
Phase 3 输出：数据富化 + 结构化落盘

v1 的问题与修复：
  - geoip2 未列入 requirements，导致 GeoIP 永远静默返回 {} → 现在把它列为可选依赖，
    缺库时打印一次提示（而不是假装成功），并支持 ASN 库。
  - 只支持 JSON 数组且写入是同步阻塞 → 增加 --format jsonl（边发现边可读、可 tail）
    与原子化收尾（先写临时文件再改名，避免中途 Ctrl-C 留下半个 JSON）。
  - 命中节点没有「为什么命中」的证据字段 → 现在 evidence 由 verifier 一并落盘。
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("reality-cf.reporter")

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    C_GREEN, C_YELLOW, C_CYAN, C_DIM, C_RESET = (
        Fore.GREEN, Fore.YELLOW, Fore.CYAN, Style.DIM, Style.RESET_ALL,
    )
except ImportError:  # colorama 是可选依赖
    C_GREEN = C_YELLOW = C_CYAN = C_DIM = C_RESET = ""

DEFAULT_CITY_DB = "/usr/share/GeoIP/GeoLite2-City.mmdb"
DEFAULT_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

_geoip_cache: dict[str, object] = {}
_geoip_warned = False


class Reporter:
    """流式写盘：命中一条写一条，中断也不丢已发现的结果。"""

    def __init__(self, output_path: str, fmt: str = "json"):
        self.output_path = Path(output_path)
        self.fmt = fmt if fmt in ("json", "jsonl") else "json"
        self.count = 0
        self._tmp: Path | None = None
        self._fp = None

    # ── 生命周期 ──
    def start(self) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.output_path.name + ".", suffix=".part",
            dir=str(self.output_path.parent),
        )
        os.close(fd)
        self._tmp = Path(tmp_name)
        self._fp = open(self._tmp, "w", encoding="utf-8")
        if self.fmt == "json":
            self._fp.write("[\n")

    def on_result(self, result: dict) -> None:
        result = dict(result)
        result.setdefault("geo", _lookup_geo(result.get("ip", "")))
        result.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))

        self.count += 1
        if self.fmt == "json":
            if self.count > 1:
                self._fp.write(",\n")
            json.dump(result, self._fp, ensure_ascii=False, indent=2)
        else:
            self._fp.write(json.dumps(result, ensure_ascii=False) + "\n")
        self._fp.flush()

        self._print_row(result)

    def finish(self) -> int:
        if self._fp is None:
            return self.count
        if self.fmt == "json":
            self._fp.write("\n]\n" if self.count else "]\n")
        self._fp.flush()
        os.fsync(self._fp.fileno())
        self._fp.close()
        self._fp = None
        if self._tmp is not None:
            os.replace(self._tmp, self.output_path)   # 原子替换
            self._tmp = None
        usable = sum(1 for r in getattr(self, "_rows", []) if r.get("usable") is True)
        if any(r.get("usable") is not None for r in getattr(self, "_rows", [])):
            logger.info("共发现 %d 个命中，其中认证可用 %d 个 → %s（%s）",
                        self.count, usable, self.output_path, self.fmt)
        else:
            logger.info("共发现 %d 个命中（未经认证复核）→ %s（%s）",
                        self.count, self.output_path, self.fmt)
        return self.count

    def abort(self) -> None:
        """异常退出时保留已写入内容，不删除 .part 文件。"""
        if self._fp is not None:
            try:
                self._fp.flush()
                self._fp.close()
            except Exception:
                pass
            self._fp = None
        if self._tmp is not None and self._tmp.exists():
            try:
                os.replace(self._tmp, self.output_path)
            except Exception:
                pass

    # ── 展示 ──
    def _print_row(self, r: dict) -> None:
        self._rows = getattr(self, "_rows", [])
        self._rows.append(r)
        geo = r.get("geo") or {}
        loc = geo.get("country") or "??"
        if geo.get("city"):
            loc += "/" + str(geo["city"])
        asn = geo.get("asn") or ""
        ev = r.get("evidence") or {}
        usable = r.get("usable")
        if usable is True:
            tag = f"{C_GREEN}✅ 可用{C_RESET}"
        elif usable is False:
            tag = f"{C_YELLOW}⚠️  {r.get('auth_error') or '不可用'}{C_RESET}"
        else:
            tag = f"{C_GREEN}✅{C_RESET}"
        extra = "" if usable is None else f"  {C_DIM}auth={r.get('auth_error') or 'ok'}{C_RESET}"
        print(
            f"  {tag} {C_CYAN}{r.get('ip')}:{r.get('port')}{C_RESET}  "
            f"{C_YELLOW}{r.get('target_sni')}{C_RESET}  [{loc}] "
            f"{C_DIM}{asn} cf-ray={ev.get('cf_ray') or '-'}{C_RESET}{extra}"
        )


def print_summary(stats: dict) -> None:
    """把「为什么没命中」摊开给用户看，避免 0 结果时无从判断。"""
    total = stats.get("total", 0)
    hit = stats.get("hit", 0)
    print()
    print(f"{C_CYAN}──────── 验证统计 ────────{C_RESET}")
    print(f"  目标总数        {total}")
    print(f"  命中            {C_GREEN}{hit}{C_RESET}")
    if total:
        print(f"  连接/握手失败   {stats.get('probe_fail', 0)}")
        print(f"  无证书          {stats.get('no_cert', 0)}")
        print(f"  证书不匹配 SNI  {stats.get('name_mismatch', 0)}")
        print(f"  Step2 握手失败  {stats.get('step2_tls_fail', 0)}")
        print(f"  无 CF 特征头    {stats.get('no_cf', 0)}")
        print(f"  判定为蜜罐      {stats.get('honeypot', 0)}")
    auth = stats.get("auth") or {}
    if auth:
        print(f"  认证可用        {C_GREEN}{auth.get('usable', 0)}{C_RESET}")
        if auth.get("auth_failed"):
            print(f"  凭证失效        {auth['auth_failed']}   ← 真 REALITY 但 uuid/pbk/sid 已过期")
        if auth.get("not_reality"):
            print(f"  不是 REALITY    {auth['not_reality']}   ← 收到真证书，实为普通 TLS 反代")
        if auth.get("timeout"):
            print(f"  复核超时        {auth['timeout']}")
        if auth.get("other"):
            print(f"  无法复核        {auth['other']}   ← 缺凭证或内核未找到")
        saved = auth.get("cache", 0) + auth.get("sibling", 0)
        if saved:
            print(f"  省掉的复核      {saved}   ← 缓存 {auth.get('cache',0)} / 同凭证 {auth.get('sibling',0)}")
        if auth.get("skipped"):
            print(f"  提前跳过        {auth['skipped']}   ← 已达 --min-usable")
    if stats.get("dup_hit"):
        print(f"  重复命中(忽略)  {stats['dup_hit']}   ← --sni-list 笛卡尔积放大的部分")
    if stats.get("errors"):
        print(f"  异常            {stats['errors']}")
    if total and not hit:
        print(f"{C_YELLOW}  提示：命中 0 时优先看「证书不匹配 SNI」与「无 CF 特征头」这两栏。{C_RESET}")
    print(f"{C_CYAN}──────────────────────────{C_RESET}")


# ══════════════════════════════════════════════════════════════
# GeoIP（可选）
# ══════════════════════════════════════════════════════════════

def _lookup_geo(ip: str) -> dict:
    global _geoip_warned
    if not ip:
        return {}

    city_db = os.environ.get("GEOIP_DB", DEFAULT_CITY_DB)
    asn_db = os.environ.get("GEOIP_ASN_DB", DEFAULT_ASN_DB)
    if not Path(city_db).exists() and not Path(asn_db).exists():
        return {}

    try:
        import geoip2.database  # noqa: F401
    except ImportError:
        if not _geoip_warned:
            logger.info("未安装 geoip2，Geo 字段留空（pip install geoip2 可启用）")
            _geoip_warned = True
        return {}

    geo: dict = {}
    if Path(city_db).exists():
        try:
            reader = _reader(city_db, "city")
            rec = reader.city(ip)
            geo["country"] = rec.country.iso_code or ""
            geo["city"] = rec.city.name or ""
        except Exception:
            pass
    if Path(asn_db).exists():
        try:
            reader = _reader(asn_db, "asn")
            rec = reader.asn(ip)
            geo["asn"] = f"AS{rec.autonomous_system_number} {rec.autonomous_system_organization or ''}".strip()
        except Exception:
            pass
    return geo


def _reader(path: str, kind: str):
    key = f"{kind}:{path}"
    if key not in _geoip_cache:
        import geoip2.database

        _geoip_cache[key] = geoip2.database.Reader(path)
    return _geoip_cache[key]
