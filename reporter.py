"""
Phase 3: 数据富化 + 结构化输出模块
GeoIP, ASN, 终端实时打印, 流式 JSON 写入
"""

import json, os, logging
from datetime import datetime

logger = logging.getLogger("reality-cf.reporter")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    C_GREEN  = Fore.GREEN
    C_YELLOW = Fore.YELLOW
    C_CYAN   = Fore.CYAN
    C_RESET  = Style.RESET_ALL
except ImportError:
    C_GREEN = C_YELLOW = C_CYAN = C_RESET = ""


class Reporter:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.count = 0
        self._fp = None

    def start(self):
        self._fp = open(self.output_path, "w", encoding="utf-8")
        self._fp.write("[\n")

    def on_result(self, result: dict):
        # 数据富化: GeoIP (尝试本地 MaxMind)
        result["geo"] = _lookup_geo(result["ip"])
        result["timestamp"] = datetime.now().isoformat()

        self.count += 1

        # 终端打印
        geo = result["geo"]
        tag = f"{C_GREEN}✅{C_RESET}"
        print(
            f"  {tag} {C_CYAN}{result['ip']}:{result['port']}{C_RESET}  "
            f"{C_YELLOW}{result['target_sni']}{C_RESET}  "
            f"[{geo.get('country', '??')}] {geo.get('asn', '')}"
        )

        # 流式写入 JSON
        if self.count > 1:
            self._fp.write(",\n")
        json.dump(result, self._fp, ensure_ascii=False, indent=2)

    def finish(self):
        self._fp.write("\n]\n")
        self._fp.close()
        logger.info(f"共发现 {self.count} 个漏洞节点 → {self.output_path}")


def _lookup_geo(ip: str) -> dict:
    """
    GeoIP 查本地 MaxMind 数据库。
    支持:
      - GEOIP_DB 环境变量指向 GeoLite2-City.mmdb
      - 默认路径: /usr/share/GeoIP/GeoLite2-City.mmdb
    无数据库时返回空。
    """
    db_path = os.environ.get("GEOIP_DB", "/usr/share/GeoIP/GeoLite2-City.mmdb")
    if not os.path.exists(db_path):
        return {}

    try:
        import geoip2.database
        reader = _geoip_reader(db_path)
        resp = reader.city(ip)
        return {
            "country": resp.country.iso_code or "??",
            "city": resp.city.name or "",
            "asn": "",
        }
    except ImportError:
        pass
    except Exception:
        pass

    return {}


_geoip_cache = {}
def _geoip_reader(path: str):
    if path not in _geoip_cache:
        import geoip2.database
        _geoip_cache[path] = geoip2.database.Reader(path)
    return _geoip_cache[path]
