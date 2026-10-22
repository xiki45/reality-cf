"""
认证复核结果缓存

为什么要有：同一个订阅里常有多个入口共用一套凭证（同 uuid + pbk + sid），
本轮实测 144.31.0.140 与 138.124.4.224 就是同一家。凭证失效时，
这两个入口的认证必然一起失败 —— 第二个不必再起一次内核进程去试。

缓存键是「凭证指纹」，不是节点 IP：
  - 凭证不变而 IP 变了 → 命中缓存，仍然有效（同一批机器换了入口）
  - 凭证换了（订阅更新）→ 指纹变化，自动失效
  - 节点死了但凭证没换 → 由 TTL 兜底，到期后重新实测

对应三类跳过，日志里可区分：
  cache   命中本地缓存（跨次运行）
  sibling 本轮内同凭证的兄弟节点已经测过
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time

logger = logging.getLogger("reality-cf.authcache")

__all__ = ["fingerprint", "AuthCache", "DEFAULT_TTL"]

DEFAULT_TTL = 6 * 3600


def fingerprint(node: dict) -> str:
    """凭证指纹：uuid + 公钥 + short-id（与节点地址无关）。"""
    raw = "|".join([
        str(node.get("uuid") or ""),
        str(node.get("pbk") or ""),
        str(node.get("sid") or ""),
    ])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class AuthCache:
    """极简 JSON 缓存，读写都在内存里，save() 时原子落盘。"""

    def __init__(self, path: str | None = None, ttl: int = DEFAULT_TTL):
        self.path = path
        self.ttl = ttl
        self._data: dict[str, dict] = {}
        self._dirty = False
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    self._data = json.load(fh) or {}
            except Exception as exc:
                logger.warning("认证缓存读取失败，忽略: %s", exc)
                self._data = {}

    def get(self, fp: str) -> dict | None:
        hit = self._data.get(fp)
        if not hit:
            return None
        if self.ttl > 0 and time.time() - float(hit.get("ts", 0)) > self.ttl:
            return None
        return hit

    def put(self, fp: str, info: dict) -> None:
        self._data[fp] = {
            "usable": bool(info.get("usable")),
            "auth_error": info.get("auth_error") or "",
            "ts": time.time(),
        }
        self._dirty = True

    def save(self) -> None:
        if not (self.path and self._dirty):
            return
        tmp = f"{self.path}.part"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self._data, fh, indent=0)
            os.replace(tmp, self.path)
            self._dirty = False
        except Exception as exc:
            logger.warning("认证缓存写入失败: %s", exc)

    def __len__(self) -> int:
        return len(self._data)
