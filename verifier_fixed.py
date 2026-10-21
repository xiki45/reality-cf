"""
兼容 shim。

v1 检验阶段这里是「修好握手的参考实现」，用于对照原 verifier.py 的缺陷。
v2 已把全部修复并入 verifier.py 本体，本文件仅为历史引用（报告/文档里的链接）保留。
"""

from verifier import (  # noqa: F401
    Stats,
    cert_match,
    get_stats,
    reset_stats,
    verify_batch,
    verify_single,
)

__all__ = [
    "Stats", "cert_match", "get_stats", "reset_stats",
    "verify_batch", "verify_single",
]
