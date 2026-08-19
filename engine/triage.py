"""崩溃分类 / 去重 / 最小化 —— P5 负责（D2~D4）。

解析 ASan/UBSan 的 stderr，输出结构化 CrashInfo：
- heap-buffer-overflow / stack-buffer-overflow：ASan "SUMMARY: AddressSanitizer: ..."
- heap-use-after-free：ASan 同类报告
- integer-overflow：UBSan "runtime error: ... signed integer overflow" 等
- 无法识别归入 "unknown"

去重键建议：vuln_type + 栈顶位置。最小化可用 Executor 反复验证崩溃仍触发。

接口契约见 contract.py（CrashInfo），签名不可改。
"""
from __future__ import annotations

from contract import CrashInfo


def classify_crash(stderr: bytes, input_path: str) -> CrashInfo:
    """解析崩溃 stderr，分类漏洞类型并生成去重键 / 复现命令。"""
    raise NotImplementedError("P5 D2~D4 实现：ASan/UBSan 解析 + 去重 + 最小化")
