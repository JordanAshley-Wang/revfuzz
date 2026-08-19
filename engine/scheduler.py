"""能量调度 —— P4 王渊明 负责（D2~D4）。

VPGFUZZ 极简版落地：风险加权能量调度。
核心公式（创新点 3）：种子得分 score = cov_score × (1 + risk_weight)

- cov_score（AFL 风格覆盖得分）：以 found_edges（首次入队贡献的新边数）为稀缺性代理，
  新边贡献越多越珍贵；再叠加 exec_count 的新鲜度衰减，避免单一种子霸占执行。
- risk_weight（静态风险权重）：近似「种子命中边与静态高风险函数的交集占比」。
  契约限制下 Seed 只存 found_edges 计数（不含逐边集合），故用
  「目标高风险代码占比 × 种子覆盖深度」近似该交集占比，覆盖越深的种子越可能触达
  敏感 API 密集区域，从而获得更高能量（VPGFUZZ 思想）。
- 选种：把 score 线性映射到能量 [1, 32]，以能量为权重做轮盘赌（random.choices）。

analysis 为空时 risk_weight = 0，退化为纯覆盖调度（仍可工作）。
接口契约见 contract.py（Seed），签名不可改。
"""
from __future__ import annotations

import random

from contract import Seed

_ENERGY_MIN = 1.0
_ENERGY_MAX = 32.0
# 新鲜度衰减系数：exec_count 每 +1，新鲜度下降 2%（约 50 次后减半）
_NOVELTY_DECAY = 0.02


# ================= 静态风险画像 =================

def _high_risk_density(analysis: dict) -> float:
    """目标高风险代码占比（0~1）：高风险函数体积 / 总函数体积。

    高风险函数判定（对未知量纲的 risk_score 做尺度无关处理）：
    - 出现在 dangerous_calls 中且 risk ∈ {high, medium} 的函数名；
    - 或 risk_score ≥ 全量最大 risk_score 的 50%（示例 7.5 属高危，1~2 属低危）。
    """
    if not analysis:
        return 0.0
    funcs = [f for f in analysis.get("functions", []) if isinstance(f, dict)]
    if not funcs:
        return 0.0

    high_names = {
        str(d.get("function"))
        for d in analysis.get("dangerous_calls", [])
        if isinstance(d, dict) and str(d.get("risk", "")).lower() in ("high", "medium")
    }

    risks = []
    for f in funcs:
        try:
            risks.append(float(f.get("risk_score", 0.0)))
        except (TypeError, ValueError):
            risks.append(0.0)
    threshold = (max(risks) * 0.5) if risks else 0.0

    total = 0.0
    high = 0.0
    for f, rs in zip(funcs, risks):
        size = max(0, int(f.get("size", 0) or 0))
        total += size
        if str(f.get("name")) in high_names or (rs > 0 and rs >= threshold):
            high += size
    return (high / total) if total > 0 else 0.0


# ================= 能量调度 =================

def _coverage_score(seed: Seed) -> float:
    """AFL 风格覆盖得分：新边贡献（稀缺性）× 新鲜度衰减。"""
    favor = 1.0 + seed.found_edges
    novelty = 1.0 / (1.0 + _NOVELTY_DECAY * seed.exec_count)
    return favor * novelty


def _risk_weight(seed: Seed, density: float) -> float:
    """静态风险权重：近似「种子命中边 ∩ 高风险函数」占比。

    = 高风险代码占比 × 覆盖深度；覆盖深度用 found_edges 饱和到 [0,1)。
    """
    if density <= 0.0:
        return 0.0
    depth = seed.found_edges / (seed.found_edges + 8.0)
    return density * depth


def _score_to_energy(score: float, lo: float, hi: float) -> float:
    """把 score 线性映射到能量 [1, 32]（与 score 成正比）。"""
    if hi <= lo:
        return (_ENERGY_MIN + _ENERGY_MAX) / 2.0
    return _ENERGY_MIN + (_ENERGY_MAX - _ENERGY_MIN) * (score - lo) / (hi - lo)


def pick_seed(queue: list[Seed], analysis: dict) -> Seed:
    """从队列中按「风险加权能量」轮盘赌选出一个种子进入本轮变异。

    score = cov_score × (1 + risk_weight)；能量 [1,32] 与 score 成正比；
    以能量为权重做轮盘赌。risk_weight 结果回写 seed.risk_score（供统计/报告）。
    """
    if not queue:
        raise ValueError("pick_seed: 空语料队列")

    density = _high_risk_density(analysis)

    scores: list[float] = []
    for seed in queue:
        cov = _coverage_score(seed)
        risk = _risk_weight(seed, density)
        score = cov * (1.0 + risk)
        seed.risk_score = 1.0 + risk  # 回写静态风险分（1 为基线）
        scores.append(score)

    lo, hi = min(scores), max(scores)
    energies = [_score_to_energy(s, lo, hi) for s in scores]

    return random.choices(queue, weights=energies, k=1)[0]
