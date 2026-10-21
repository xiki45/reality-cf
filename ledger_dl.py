"""
TLS 账本自动下载（Rapid7 Project Sonar）

v1 的三处假设在当前环境全部失效，已按现行接口重写：
  1. `https://opendata.rapid7.com/sonar.ssl/index.json` → 现为 301 + 404；
     正确入口是 `https://us.api.insight.rapid7.com/opendata/studies/`。
  2. 索引结构不是 `[{files:[{name,download_url}]}]`，而是 `[{uniqid, sonarfile_set:[...]}]`。
  3. 接口需要 `X-API-Key`（账号申请），无 key 返回 401 —— 此时给出明确指引而不是静默失败。

同时：
  - 只下最新 N 个文件（Sonar SSL 单个数据集动辄数 GB~数十 GB），默认 1；
  - 下载后写 manifest.json（文件名 → 端口），供 fetcher 推断端口；
  - 校验 gzip 魔数，避免把 HTML 错误页存成 .gz；
  - 断点续传式跳过：已存在且大小非 0 的文件不重复下载。
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import os
import re
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("reality-cf.ledger")

SONAR_STUDIES_API = "https://us.api.insight.rapid7.com/opendata/studies/"
SONAR_STUDY_ID = "sonar.ssl"
DEFAULT_PORTS = [443, 8443, 2053, 2083, 2087, 2096]
MAX_CACHE_DAYS = 14
GZIP_MAGIC = b"\x1f\x8b"
_PORT_IN_NAME_RE = re.compile(r"(?:port[-_]?)(\d{2,5})", re.IGNORECASE)


def _api_key() -> str | None:
    key = os.environ.get("SONAR_API_KEY") or os.environ.get("RAPID7_API_KEY")
    return key.strip() if key else None


async def fetch_sonar_index(api_key: str | None = None) -> list[dict]:
    """取 studies 列表；无 key 或失败时返回空列表（调用方据此跳过 Phase 1B）。"""
    import aiohttp

    key = api_key or _api_key()
    if not key:
        logger.warning(
            "未配置 SONAR_API_KEY，跳过自动下载 TLS 账本。\n"
            "       申请：https://opendata.rapid7.com/apihelp/ （需 Sonar Data 账号）\n"
            "       临时替代：git clone 后手动放账本到 --ledger 目录，或直接用 --targets 给 IP 清单"
        )
        return []

    headers = {"X-Api-Key": key}
    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            async with session.get(
                SONAR_STUDIES_API, timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                if resp.status == 401:
                    logger.warning("Sonar API 鉴权失败（401），请检查 SONAR_API_KEY")
                    return []
                if resp.status != 200:
                    logger.warning("Sonar studies 接口返回 HTTP %s", resp.status)
                    return []
                data = await resp.json()
    except Exception as exc:
        logger.warning("获取 Sonar studies 失败: %s", type(exc).__name__)
        return []

    return data if isinstance(data, list) else data.get("studies", [])


def _study_files(study: dict) -> list[tuple[str, str | None]]:
    """兼容 sonarfile_set 里是字符串或 {name, download_url} 两种形态。"""
    out: list[tuple[str, str | None]] = []
    for item in study.get("sonarfile_set", []) or []:
        if isinstance(item, str):
            out.append((item, None))
        elif isinstance(item, dict):
            name = item.get("name") or item.get("key")
            if name:
                out.append((str(name), item.get("download_url") or item.get("url")))
    return out


def _candidate_urls(name: str, hint: str | None) -> list[str]:
    urls = []
    if hint:
        urls.append(hint)
    urls.append(f"{SONAR_STUDIES_API}{SONAR_STUDY_ID}/{name}")
    urls.append(f"https://opendata.rapid7.com/sonar.ssl/{name}")
    urls.append(f"https://sonardata.rapid7.com/sonar.ssl/{name}")
    return urls


async def download_ledger(
    cache_dir: str = "./scans",
    ports: list[int] | None = None,
    force: bool = False,
    limit: int = 1,
) -> str | None:
    """下载最新的 TLS 账本到 cache_dir；成功返回目录路径，失败返回 None。"""
    if ports is None:
        ports = DEFAULT_PORTS

    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)

    age_file = cache / ".last_update"
    if not force and age_file.exists():
        try:
            age = datetime.fromisoformat(age_file.read_text().strip())
            existing = list(cache.glob("*.json.gz"))
            if datetime.now() - age < timedelta(days=MAX_CACHE_DAYS) and existing:
                logger.info("TLS 账本缓存有效（%d 个文件，%s）", len(existing), age.date())
                return cache_dir
        except Exception:
            pass

    logger.info("获取 Sonar studies 索引...")
    studies = await fetch_sonar_index()
    if not studies:
        return None

    study = next(
        (s for s in studies if s.get("uniqid") == SONAR_STUDY_ID or s.get("name") == SONAR_STUDY_ID),
        None,
    )
    if study is None:
        logger.warning("Sonar 索引里没有 %s 数据集", SONAR_STUDY_ID)
        return None

    files = _study_files(study)
    if not files:
        logger.warning("%s 数据集没有可用文件", SONAR_STUDY_ID)
        return None

    # 只要最新的 limit 个（文件名通常带日期前缀）
    files.sort(key=lambda kv: kv[0], reverse=True)
    to_fetch = files[: max(1, limit)]
    logger.info("准备下载 %d 个账本文件（共 %d 个）", len(to_fetch), len(files))

    key = _api_key()
    headers = {"X-Api-Key": key} if key else {}
    manifest: dict[str, int] = {}
    downloaded = 0

    import aiohttp

    for name, hint in to_fetch:
        dst = cache / Path(name).name
        if dst.exists() and dst.stat().st_size > 0 and not force:
            logger.info("  已存在，跳过: %s", dst.name)
            downloaded += 1
            _record_port(manifest, dst.name)
            continue

        ok = False
        async with aiohttp.ClientSession(headers=headers) as session:
            for url in _candidate_urls(name, hint):
                try:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=3600)
                    ) as resp:
                        if resp.status != 200:
                            logger.debug("  %s → HTTP %s", url, resp.status)
                            continue
                        with open(dst, "wb") as fh:
                            async for chunk in resp.content.iter_chunked(1024 * 1024):
                                fh.write(chunk)
                except Exception as exc:
                    logger.debug("  %s 下载失败: %s", url, type(exc).__name__)
                    continue

                if _is_gzip(dst):
                    size_mb = dst.stat().st_size / (1024 * 1024)
                    logger.info("  ✓ %s (%.0f MB)", dst.name, size_mb)
                    ok = True
                    break
                logger.debug("  %s 返回的不是 gzip，丢弃", url)
                dst.unlink(missing_ok=True)

        if ok:
            downloaded += 1
            _record_port(manifest, dst.name)
        else:
            logger.warning("  ✗ %s 所有下载源均失败", name)

    if manifest:
        (cache / "manifest.json").write_text(
            json.dumps({"files": manifest, "updated": datetime.now().isoformat()}, indent=2)
        )

    if downloaded:
        age_file.write_text(datetime.now().isoformat())
        logger.info("TLS 账本就绪: %d 个文件 → %s", downloaded, cache_dir)
        return cache_dir

    logger.warning("TLS 账本下载失败，Phase 1B 将被跳过")
    return None


def _record_port(manifest: dict[str, int], filename: str) -> None:
    m = _PORT_IN_NAME_RE.search(filename)
    if not m:
        return
    try:
        port = int(m.group(1))
    except Exception:
        return
    if 0 < port < 65536:
        manifest[filename] = port


def _is_gzip(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == GZIP_MAGIC
    except Exception:
        return False


def peek_ledger(path: str, lines: int = 3) -> list[dict]:
    """调试用：看账本前几行长什么样，便于确认字段结构。"""
    out: list[dict] = []
    p = Path(path)
    opener = gzip.open if p.name.endswith(".gz") else open
    try:
        with opener(p, "rt", encoding="utf-8", errors="ignore") as fh:
            for _, line in zip(range(lines), fh):
                try:
                    out.append(json.loads(line))
                except Exception:
                    out.append({"__raw__": line[:200]})
    except Exception as exc:
        logger.warning("peek 失败: %s", exc)
    return out
