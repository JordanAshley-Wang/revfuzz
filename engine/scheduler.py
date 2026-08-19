"""能量调度 —— P4 负责（D2~D4）。

VPGFUZZ 极简版：按 P2 静态分析的风险分对种子加权选择，
高风险函数路径相关的种子获得更多变异能量。

接口契约见 contract.py（Seed），签名不可改。
"""
from __future__ import annotations

from contract import Seed


def pick_seed(queue: list[Seed], analysis: dict) -> Seed:
    """从队列中选一个种子进入本轮变异。

    - analysis 为 P2 的 analysis.json 内容（无静态分析时为空 dict，需可工作）；
    - 建议结合 Seed.risk_score / exec_count / found_edges 加权。
    """
    raise NotImplementedError("P4 D3 实现：风险加权调度")
