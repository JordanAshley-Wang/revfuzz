"""RevFuzz 接口契约 —— D1 定稿。

★ 本文件仅 P1（组长）可修改，任何变更须在站会同步全组 ★

各模块只通过此处定义的数据结构与函数签名交互：
- P2 产出 analysis.json（schema 见 ANALYSIS_REQUIRED_KEYS）
- P3 提供 CoverageRunner.run(bytes) -> RunResult
- P4 提供 mutate(...) / pick_seed(...)
- P5 提供 classify_crash(...) -> CrashInfo
- P6 提供 generate_report(CampaignStats, list[CrashInfo], analysis, fmt)
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal

# ================= P3：覆盖反馈 =================

RunStatus = Literal["ok", "crash", "timeout"]


@dataclass
class RunResult:
    """单次目标运行结果（afl-showmap 取边覆盖）。"""
    edges: set[int]          # 本次运行命中的边 id 集合
    is_new: bool             # 是否发现新边（相对全局位图）
    status: RunStatus        # "ok" | "crash" | "timeout"
    stderr: bytes            # ASan/UBSan 输出（崩溃时非空）
    exec_ms: float           # 单次执行耗时（毫秒）


# ================= P4：种子与调度 =================

@dataclass
class Seed:
    """语料队列中的一个种子。"""
    id: int
    path: str                # 落盘路径（初始种子为 corpus 内路径，新种子为 queue/ 下路径）
    data: bytes
    risk_score: float = 1.0  # 静态分析风险分加权（P4 调度依据）
    exec_count: int = 0      # 被选中执行次数（能量调度用）
    found_edges: int = 0     # 首次入队时贡献的边数


# ================= P5：崩溃分类 =================

VulnType = Literal[
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "heap-use-after-free",
    "integer-overflow",
    "unknown",
]


@dataclass
class CrashInfo:
    """一个去重后的崩溃。"""
    vuln_type: VulnType
    location: str            # 崩溃位置（如 "vuln_heap.c:23" 或符号化栈顶）
    dedup_key: str           # 去重键（同键崩溃只保留一个）
    input_path: str          # 触发崩溃的输入文件路径
    minimized_input: str | None  # 最小化后的输入路径（未最小化为 None）
    repro_cmd: str           # 复现命令
    raw_stderr: bytes = b""  # 原始 ASan/UBSan 输出


# ================= P6：测试活动统计 =================

@dataclass
class CampaignStats:
    """一次 fuzzing 活动的汇总统计（报告数据源）。"""
    target: str
    start_time: float        # time.time() 时间戳
    elapsed_s: float
    total_execs: int
    execs_per_sec: float
    edges_covered: int       # 已命中边数
    edges_total: int         # 目标静态总边数（口径：objdump 反汇编总条件跳转边数）
    crashes: int             # 崩溃总数（含重复）
    unique_crashes: int      # 去重后崩溃数（验收指标）
    timeouts: int
    corpus_size: int         # 结束时语料队列大小


# ================= P2：analysis.json schema =================

ANALYSIS_JSON_VERSION = 1

ANALYSIS_REQUIRED_KEYS = (
    "target",           # str：目标二进制路径
    "functions",        # list[{"name","addr","size","risk_score","calls"}]
    "dangerous_calls",  # list[{"function","api","addr","risk": "high"|"medium"|"low"}]
    "input_points",     # list[{"type": "argv"|"file"|"stdin", "function"}]
    "dictionary",       # list[str]：提取的字符串/magic bytes（转义形式）
    "seeds",            # list[str]：生成的初始种子路径
)


def load_analysis(path: str) -> dict:
    """加载并校验 analysis.json，缺键直接报错（P2 产出不合格要尽早暴露）。"""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    missing = [k for k in ANALYSIS_REQUIRED_KEYS if k not in data]
    if missing:
        raise ValueError(f"analysis.json 缺少必需键: {missing}（schema 见 contract.py）")
    return data
