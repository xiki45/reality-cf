"""
中转节点状态库（保鲜 + 轮换监控）

单次扫描的结果有保鲜期 —— 实测同一批 DMIT 机器 50 分钟内从 540 台掉到 2 台，
原因是机场会定时轮换 REALITY 的 dest。所以本项目的产出不能是「一次性快照」，
而应该是「带新鲜度的存活表」：

  first_seen    第一次被判定为「未认证流量转发到 CF」的时间
  last_seen     最近一次成立的时间
  alive_rounds  累计成立轮数 / total_rounds 累计观测轮数
  dest_history  对端证书名历史（dest 轮换的直接证据）
  miss_rounds   连续未成立轮数

导出时可以按 `min_alive_rounds` 过滤，只留「多轮都成立」的稳定中转。
"""

from __future__ import annotations

import json
import logging
import os
import time

logger = logging.getLogger("reality-cf.relays")

__all__ = ["RelayState", "now_iso"]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class RelayState:
    def __init__(self, path: str | None = "relay_state.json", keep_dest: int = 6):
        self.path = path
        self.keep_dest = keep_dest
        self.data: dict[str, dict] = {}
        self._dirty = False
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self.data = json.load(fh) or {}
            except Exception as exc:
                logger.warning("状态文件读取失败，忽略: %s", exc)
                self.data = {}

    # ── 记录 ──
    def hit(self, ip: str, port: int, sni: str | None = None,
            cf_ray: str | None = None, dest_names: list[str] | None = None) -> dict:
        key = f"{ip}:{port}"
        rec = self.data.get(key) or {
            "ip": ip, "port": port, "first_seen": now_iso(),
            "alive_rounds": 0, "total_rounds": 0, "miss_rounds": 0,
            "dest_history": [],
        }
        rec["alive_rounds"] = int(rec.get("alive_rounds", 0)) + 1
        rec["total_rounds"] = int(rec.get("total_rounds", 0)) + 1
        rec["miss_rounds"] = 0
        rec["last_seen"] = now_iso()
        if sni:
            rec["sni"] = sni
        if cf_ray:
            rec["cf_ray"] = cf_ray
            rec["colo"] = cf_ray.split("-")[-1]
        self._merge_dest(rec, dest_names)
        self.data[key] = rec
        self._dirty = True
        return rec

    def miss(self, ip: str, port: int, dest_names: list[str] | None = None) -> dict:
        key = f"{ip}:{port}"
        rec = self.data.get(key)
        if rec is None:
            rec = {"ip": ip, "port": port, "first_seen": now_iso(),
                   "alive_rounds": 0, "total_rounds": 0, "miss_rounds": 0,
                   "dest_history": []}
        rec["total_rounds"] = int(rec.get("total_rounds", 0)) + 1
        rec["miss_rounds"] = int(rec.get("miss_rounds", 0)) + 1
        rec["last_miss"] = now_iso()
        self._merge_dest(rec, dest_names)
        self.data[key] = rec
        self._dirty = True
        return rec

    def _merge_dest(self, rec: dict, names: list[str] | None) -> None:
        if not names:
            return
        hist = rec.setdefault("dest_history", [])
        last = hist[-1] if hist else None
        same = last and set(last.get("names", [])) == set(names)
        if not same:
            hist.append({"ts": now_iso(), "names": names[:8]})
            if len(hist) > self.keep_dest:
                del hist[0:len(hist) - self.keep_dest]
        rec["dest_current"] = names[:8]

    # ── 查询 / 导出 ──
    def active(self, max_miss: int = 0, min_alive_rounds: int = 1) -> list[dict]:
        """当前有效：最近一轮成立（miss_rounds <= max_miss）且累计成立轮数达标。"""
        out = []
        for rec in self.data.values():
            if int(rec.get("miss_rounds", 0)) > max_miss:
                continue
            if int(rec.get("alive_rounds", 0)) < min_alive_rounds:
                continue
            if not rec.get("last_seen"):
                continue
            out.append(rec)
        out.sort(key=lambda r: (-int(r.get("alive_rounds", 0)), r["ip"]))
        return out

    def rotating(self) -> list[dict]:
        """dest 发生过变化的机器 —— 这类通常会周期性把 dest 指回 CF。"""
        return [r for r in self.data.values() if len(r.get("dest_history", [])) > 1]

    def save(self) -> None:
        if not (self.path and self._dirty):
            return
        tmp = f"{self.path}.part"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False)
            os.replace(tmp, self.path)
            self._dirty = False
        except Exception as exc:
            logger.warning("状态写入失败: %s", exc)

    def export(self, path: str, active_only: bool = True,
               min_alive_rounds: int = 1, with_sni: str | None = None) -> int:
        """导出可直接使用的清单：`ip:port` 或 `ip:port:sni`。"""
        recs = self.active(min_alive_rounds=min_alive_rounds) if active_only else list(self.data.values())
        lines = []
        for r in recs:
            sni = with_sni or r.get("sni")
            lines.append(f"{r['ip']}:{r['port']}:{sni}" if sni else f"{r['ip']}:{r['port']}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
        return len(lines)

    def __len__(self) -> int:
        return len(self.data)
