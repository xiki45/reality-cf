"""
目标清单解析（不盲扫的入口）

  --targets  每行 `host` / `host:port` / `host:port:sni`
  --links    每行 `vless://…security=reality…`，把订阅里的节点连同
             它自己的 SNI 和 REALITY 凭证一起读进来

为什么要有 `:sni` 这一列：
固定一个 SNI 去问所有节点是错的 —— 每个节点 REALITY dest 各不相同，
用别人的 SNI 只会换来 `name_mismatch`。三列格式让「一个目标只跟它自己的
SNI 配对」，这是本项目唯一正确的用法。
"""

from __future__ import annotations

import ipaddress
import logging
import urllib.parse

logger = logging.getLogger("reality-cf.targets")

__all__ = ["parse_targets_file", "parse_links_file", "parse_ranges_file", "Target"]

#: (host, port, sni)；sni 为空串表示「该行没给 SNI，需要用 --sni/--sni-list 补」
Target = tuple[str, int, str]


def _split_host_port_rest(line: str) -> tuple[str, str, str] | None:
    """拆 `host:port[:sni]`，兼容 IPv6 字面量 `[::1]:443:sni`。"""
    if line.startswith("["):                       # IPv6 字面量
        end = line.find("]")
        if end < 0:
            return None
        host = line[1:end]
        rest = line[end + 1:].lstrip(":")
    else:
        host, sep, rest = line.partition(":")
        if not sep:
            return host.strip(), "", ""
        host = host.strip()
    port_s, _, sni = rest.partition(":")
    return host, port_s.strip(), sni.strip()


def parse_targets_file(path: str, default_port: int = 443) -> list[Target]:
    """
    读目标清单。支持三种行格式：

        example.com                 → example.com:443, SNI 待补
        example.com:8443            → example.com:8443, SNI 待补
        1.2.3.4:443:images.apple.com → 只跟 images.apple.com 配对（推荐）
        [::1]:443:example.com       → IPv6 同上

    `#` 开头为注释，空行跳过。返回去重后的 (host, port, sni) 列表。
    """
    out: list[Target] = []
    seen: set[Target] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = _split_host_port_rest(line)
            if not parts:
                logger.warning("  %s:%d 无法解析，跳过: %s", path, lineno, line)
                continue
            host, port_s, sni = parts
            if not host:
                continue
            port = default_port
            if port_s:
                try:
                    port = int(port_s)
                except ValueError:
                    logger.warning("  %s:%d 端口非法，跳过: %s", path, lineno, line)
                    continue
                if not 0 < port < 65536:
                    logger.warning("  %s:%d 端口越界，跳过: %s", path, lineno, line)
                    continue
            key: Target = (host, port, sni.lower())
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def parse_links_file(path: str) -> list[dict]:
    """
    读 `vless://…` 分享链接（订阅原料），每条返回：

        {link, host, port, sni, uuid, pbk, sid, flow, net, fp}

    只收 `security=reality` 的条目；缺 uuid/pbk/sni 的丢弃。
    这些字段足够让 `--verify-auth` 用真实内核做认证复核。
    """
    nodes: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#") or not line.startswith("vless://"):
                continue
            try:
                u = urllib.parse.urlsplit(line)
                p = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
            except Exception:
                logger.warning("  %s:%d 链接解析失败，跳过", path, lineno)
                continue
            if (p.get("security") or "").lower() != "reality":
                continue
            host, port, sni = u.hostname, u.port, (p.get("sni") or p.get("host") or "")
            uuid, pbk = u.username or "", p.get("pbk") or ""
            if not (host and port and uuid and pbk and sni):
                logger.warning("  %s:%d REALITY 字段不全，跳过: %s", path, lineno, host)
                continue
            key = (host, port, sni.lower())
            if key in seen:
                continue
            seen.add(key)
            nodes.append({
                "link": line,
                "host": host,
                "port": int(port),
                "sni": sni,
                "uuid": uuid,
                "pbk": pbk,
                "sid": p.get("sid") or "",
                "flow": p.get("flow") or "",
                "net": p.get("type") or "tcp",
                "fp": p.get("fp") or "chrome",
            })
    return nodes


def parse_ranges_file(path: str, ports: list[int], max_hosts: int = 200_000) -> list[Target]:
    """
    读网段清单（每行 CIDR 或单个 IP），展开成 (ip, port, "") 目标。

    这是「按机房扫」的入口：与其等订阅里冒出新节点，不如直接扫已知
    代理友好型机房的 IP 段。配合一个已知落在 Cloudflare zone 内的 SNI
    （`--sni`）即可判定「这台机器会不会把 TLS 透传给 CF」，不需要任何凭证。

    超过 max_hosts 直接报错而不是悄悄截断 —— 误扫 /8 会打出事故。
    """
    nets: list[ipaddress._BaseNetwork] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                logger.warning("  %s:%d 不是合法网段，跳过: %s", path, lineno, line)

    total = sum(n.num_addresses for n in nets) * max(1, len(ports))
    if total > max_hosts:
        raise ValueError(
            f"展开后共 {total} 个目标，超过上限 {max_hosts}。"
            f"请缩小网段、减少 --ports，或显式调大 --range-max"
        )

    out: list[Target] = []
    for net in nets:
        hosts = net.hosts() if net.num_addresses > 2 else [net.network_address]
        for ip in hosts:
            for port in ports:
                out.append((str(ip), port, ""))
    return out
