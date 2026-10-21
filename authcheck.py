"""
Phase 4: 真实客户端认证复核（可选，--verify-auth）

TLS 层探针只能证明「这个端口的未认证流量被透传到某个目标」，
证明不了「它是不是 REALITY」，更证明不了「这套凭证还能不能用」。
唯一可靠的办法是拿真实内核按 REALITY 协议握一次手。

本模块会调用本机已有的客户端内核：
  - Clash Party / Mihomo Party 自带的 sidecar mihomo（优先，用户环境一致）
  - xray（官方二进制）
  - PATH 里的 mihomo / xray

失败原因会被归类，因为它们的含义完全不同：

  auth_failed   真 REALITY，但 uuid/pbk/short-id 已失效（订阅过期）
  not_reality   端口返回了真实证书 → 根本不是 REALITY，只是 TLS 反代
  timeout       连不上 / 无响应（节点已死）
  eof           连接被对端关闭
  refused       端口拒绝连接
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import time

logger = logging.getLogger("reality-cf.auth")

__all__ = ["find_core", "verify_node", "TEST_URL"]

TEST_URL = "https://www.gstatic.com/generate_204"

_CORE_CANDIDATES = [
    ("/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo", "mihomo"),
    ("/Applications/Mihomo Party.app/Contents/Resources/sidecar/mihomo", "mihomo"),
    ("/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo", "mihomo"),
    ("/Applications/ClashX Meta.app/Contents/Resources/mihomo", "mihomo"),
    ("/opt/homebrew/bin/mihomo", "mihomo"),
    ("/usr/local/bin/mihomo", "mihomo"),
    ("/opt/homebrew/bin/xray", "xray"),
    ("/usr/local/bin/xray", "xray"),
]

_ERROR_MAP = [
    ("reality authentication failed", "auth_failed"),
    ("received real certificate", "not_reality"),
    ("i/o timeout", "timeout"),
    ("context deadline exceeded", "timeout"),
    ("connection refused", "refused"),
    ("connect error: eof", "eof"),
    ("unexpected eof", "eof"),
]


def find_core(explicit: str | None = None) -> tuple[str, str] | None:
    """返回 (内核路径, "mihomo"|"xray")；显式指定的优先。"""
    if explicit:
        if not os.path.exists(explicit):
            return None
        kind = "xray" if "xray" in os.path.basename(explicit).lower() else "mihomo"
        return explicit, kind
    for path, kind in _CORE_CANDIDATES:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path, kind
    for name, kind in (("mihomo", "mihomo"), ("xray", "xray")):
        found = shutil.which(name)
        if found:
            return found, kind
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mihomo_config(node: dict, port: int) -> str:
    lines = [
        f"mixed-port: {port}",
        "mode: rule",
        "log-level: warning",
        "proxies:",
        '  - name: "N"',
        "    type: vless",
        f'    server: {node["host"]}',
        f'    port: {node["port"]}',
        f'    uuid: {node["uuid"]}',
        "    udp: false",
        "    tls: true",
        f'    network: {node.get("net") or "tcp"}',
        f'    servername: {node["sni"]}',
        f'    client-fingerprint: {node.get("fp") or "chrome"}',
    ]
    if node.get("flow"):
        lines.append(f'    flow: {node["flow"]}')
    lines += ["    reality-opts:", f'      public-key: {node["pbk"]}']
    if node.get("sid"):
        lines.append(f'      short-id: "{node["sid"]}"')
    lines += [
        "proxy-groups:", "  - name: P", "    type: select",
        "    proxies:", "      - N", "rules:", "  - MATCH,P",
    ]
    return "\n".join(lines) + "\n"


def _xray_config(node: dict, port: int) -> str:
    stream = {
        "network": node.get("net") or "tcp",
        "security": "reality",
        "realitySettings": {
            "serverName": node["sni"],
            "fingerprint": node.get("fp") or "chrome",
            "publicKey": node["pbk"],
            "shortId": node.get("sid") or "",
        },
    }
    user = {"id": node["uuid"], "encryption": "none"}
    if node.get("flow"):
        user["flow"] = node["flow"]
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": node["host"], "port": node["port"],
                                    "users": [user]}]},
            "streamSettings": stream,
        }],
    }
    return json.dumps(cfg, indent=1)


def _classify(log: str, http_code: str) -> str:
    if http_code == "204":
        return ""
    low = (log or "").lower()
    for needle, code in _ERROR_MAP:
        if needle in low:
            return code
    if not http_code or http_code == "000":
        return "timeout"
    return f"http_{http_code}"


def verify_node(core: str, kind: str, node: dict, timeout: float = 9.0) -> dict:
    """用真实内核跑一次完整 REALITY 握手 + HTTP 请求。"""
    port = _free_port()
    workdir = tempfile.mkdtemp(prefix="realitycf-auth-")
    cfg_path = os.path.join(workdir, "config.yaml" if kind == "mihomo" else "config.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        fh.write(_mihomo_config(node, port) if kind == "mihomo" else _xray_config(node, port))

    args = [core, "-d", workdir, "-f", cfg_path] if kind == "mihomo" else [core, "run", "-c", cfg_path]
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    log = ""
    try:
        for _ in range(40):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    break
            except Exception:
                time.sleep(0.08)

        proxy = f"http://127.0.0.1:{port}" if kind == "mihomo" else f"socks5h://127.0.0.1:{port}"
        cmd = ["curl", "-sS", "-x", proxy, "-m", str(int(timeout)),
               "-o", "/dev/null", "-w", "%{http_code}", TEST_URL]
        try:
            code = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout + 12).stdout.strip()
        except Exception:
            code = ""
        time.sleep(0.25)
    finally:
        proc.terminate()
        try:
            log = proc.communicate(timeout=3)[0] or ""
        except Exception:
            proc.kill()
            log = ""
        shutil.rmtree(workdir, ignore_errors=True)

    err = _classify(log, code)
    return {
        "usable": err == "",
        "http_code": code,
        "auth_error": err,
        "core": os.path.basename(core),
    }
