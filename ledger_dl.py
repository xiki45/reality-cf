"""
TLS 账本自动下载模块
从 Rapid7 Project Sonar 拉取最新的 TLS 扫描数据
"""

import asyncio, gzip, os, json, shutil, logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("reality-cf.ledger")

SONAR_BASE = "https://opendata.rapid7.com/sonar.ssl/"
DEFAULT_PORTS = [443, 8443, 2053, 2083, 2096, 2443]
MAX_CACHE_DAYS = 14  # 超过此天数重新下载


async def fetch_sonar_index() -> list[dict]:
    """获取 Sonar SSL 数据集的 JSON 索引"""
    import aiohttp
    try:
        async with aiohttp.ClientSession() as session:
            url = f"{SONAR_BASE}index.json"
            async with session.get(url, timeout=aiohttp.ClientTimeout(30)) as resp:
                if resp.status == 200:
                    return await resp.json()
    except Exception as e:
        logger.warning(f"获取 Sonar 索引失败: {e}")
    return []


async def download_ledger(
    cache_dir: str = "./scans",
    ports: list[int] = None,
    force: bool = False,
) -> str | None:
    """
    自动下载最新的 TLS 账本文件到 cache_dir。
    返回下载目录路径，失败返回 None。
    """
    if ports is None:
        ports = DEFAULT_PORTS

    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)

    # 检查缓存是否过期
    age_file = cache / ".last_update"
    if not force and age_file.exists():
        try:
            age = datetime.fromisoformat(age_file.read_text().strip())
            if datetime.now() - age < timedelta(days=MAX_CACHE_DAYS):
                existing = list(cache.glob("port-*.json.gz"))
                if existing:
                    logger.info(f"TLS 账本缓存有效 ({len(existing)} 文件, {age.date()})")
                    return cache_dir
        except Exception:
            pass

    # 获取索引
    logger.info("获取 Sonar SSL 索引...")
    index = await fetch_sonar_index()
    if not index:
        return None

    # 找最新的数据集
    datasets = index if isinstance(index, list) else index.get("datasets", [])
    if not datasets:
        logger.warning("Sonar 索引为空")
        return None

    # 收集所有匹配端口的文件 URL
    import aiohttp
    to_download = []
    for ds in datasets:
        files = ds.get("files", [])
        if isinstance(files, str):
            continue  # skip non-list
        for f in files:
            fname = f.get("name", "") or f.get("key", "")
            if ".json.gz" not in fname:
                continue
            for port in ports:
                if f"https_{port}" in fname or f"port-{port}" in fname or f"_{port}" in fname:
                    dl_url = f.get("download_url", "") or f.get("url", "")
                    if not dl_url and "name" in f:
                        dl_url = f"{SONAR_BASE}{f['name']}"
                    if dl_url:
                        to_download.append((port, dl_url, fname))
                        break

    if not to_download:
        logger.warning("未找到匹配端口的 TLS 账本文件")
        return None

    logger.info(f"下载 {len(to_download)} 个 TLS 账本文件...")

    async def download_one(port: int, url: str, fname: str):
        dst = cache / f"port-{port}-tls.json.gz"
        if dst.exists() and not force:
            return
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(600)) as resp:
                    if resp.status == 200:
                        with open(dst, "wb") as f:
                            async for chunk in resp.content.iter_chunked(1024 * 1024):
                                f.write(chunk)
                        size_mb = dst.stat().st_size / (1024 * 1024)
                        logger.info(f"  ✓ port {port}: {size_mb:.0f} MB")
        except Exception as e:
            logger.warning(f"  ✗ port {port}: {e}")

    await asyncio.gather(*[download_one(p, u, n) for p, u, n in to_download])

    # 写入时间戳
    age_file.write_text(datetime.now().isoformat())

    remaining = list(cache.glob("port-*.json.gz"))
    logger.info(f"TLS 账本已就绪: {len(remaining)} 个文件")

    return cache_dir if remaining else None
