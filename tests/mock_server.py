"""
多场景本地 mock 服务：为验证器提供可离线复现的「节点行为样本」。

场景（端口可改，默认 18443 起）：
  cf_any_sni       任意 SNI 都回 CF 特征头            → 蜜罐 / 无差别反代
  plain_tls        普通 TLS 站点（nginx），无 CF 头     → 应被 no_cf 丢弃
  cf_sni_filtered  只对 --cf-domain 回 CF 头，其余 SNI 握后即断 → 正确命中
  non_cf_target    任意 SNI 都回普通头                 → 应被 no_cf 丢弃
  wrong_cert       证书 SAN 与目标 SNI 不匹配          → 应被 name_mismatch 丢弃
  tls_refuse       不做 TLS，直接断链                  → 应被 probe_fail 丢弃
  tarpit           只接 TCP 不回任何数据（黑洞）        → 用来验证流式时序

单独运行（供 CLI 测试）：python tests/mock_server.py
"""

from __future__ import annotations

import asyncio
import ssl
import sys
from pathlib import Path

CERTS = Path(__file__).resolve().parent / "certs"
CF_DOMAIN = "speed.cloudflare.com"

CF_RESP = (
    "HTTP/1.1 200 OK\r\n"
    "Date: Wed, 22 Oct 2026 00:00:00 GMT\r\n"
    "Content-Type: text/html\r\n"
    "Server: cloudflare\r\n"
    "CF-RAY: 8f2c1a3b9d4e5f6g-HKG\r\n"
    "Connection: close\r\n"
    "Content-Length: 2\r\n\r\n"
    "ok"
)

PLAIN_RESP = (
    "HTTP/1.1 200 OK\r\n"
    "Server: nginx/1.24.0\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "Content-Length: 2\r\n\r\n"
    "hi"
)

DEFAULT_PORTS = {
    "cf_any_sni": 18443,
    "plain_tls": 18444,
    "cf_sni_filtered": 18445,
    "non_cf_target": 18446,
    "wrong_cert": 18447,
    "tls_refuse": 18448,
    "tarpit": 18449,
}


def _context(cert: str, key: str, allowed_sni: set[str] | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERTS / cert), str(CERTS / key))
    if allowed_sni is not None:
        # 服务端拿不到 server_hostname（实测为 None），只能在握手阶段用 sni_callback 拦截
        def _cb(_sslobj, server_name, _sslctx):
            if (server_name or "").lower() in allowed_sni:
                return None
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

        ctx.sni_callback = _cb
    return ctx


def _handler(scenario: str):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            if scenario == "tls_refuse":
                writer.close()
                return

            if scenario == "cf_any_sni":
                resp = CF_RESP          # 无差别回 CF 头 → 蜜罐
            elif scenario == "cf_sni_filtered":
                resp = CF_RESP          # 只有白名单 SNI 能握手成功（由 sni_callback 保证）
            else:
                resp = PLAIN_RESP

            try:
                await asyncio.wait_for(reader.read(8192), timeout=2.0)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                pass
            writer.write(resp.encode())
            await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return handle


async def _tarpit(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """接受 TCP 后什么都不回，让客户端在 TLS 握手阶段等到超时。"""
    try:
        await asyncio.sleep(30)
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def start(
    ports: dict[str, int] | None = None,
    allow_sni: set[str] | None = None,
) -> dict[str, asyncio.AbstractServer]:
    ports = ports or DEFAULT_PORTS
    allow_sni = allow_sni or {"images.apple.com", "speed.cloudflare.com"}
    apple = _context("cert.pem", "key.pem")
    apple_filtered = _context("cert.pem", "key.pem", allowed_sni=allow_sni)
    wrong = _context("wrong.pem", "wrong-key.pem")

    servers: dict[str, asyncio.AbstractServer] = {}
    for scenario, port in ports.items():
        if scenario == "wrong_cert":
            ctx = wrong
        elif scenario == "cf_sni_filtered":
            ctx = apple_filtered
        else:
            ctx = apple
        if scenario == "tarpit":
            servers[scenario] = await asyncio.start_server(_tarpit, "127.0.0.1", port)
            continue
        servers[scenario] = await asyncio.start_server(
            _handler(scenario), "127.0.0.1", port, ssl=ctx
        )
    return servers


async def serve_forever() -> None:
    servers = await start()
    ports = {k: v for k, v in DEFAULT_PORTS.items()}
    print("mock server up: " + ", ".join(f"{k}={v}" for k, v in ports.items()), flush=True)
    await asyncio.gather(*[s.serve_forever() for s in servers.values()])


if __name__ == "__main__":
    try:
        asyncio.run(serve_forever())
    except KeyboardInterrupt:
        sys.exit(0)
