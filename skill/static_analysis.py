"""逆向 Skill：静态分析 —— P2 负责（D2~D4）。

用 capstone + pyelftools 对 ELF 做静态分析，固化人工逆向流程：
- 函数定位：解析符号表/反汇编划定函数边界；
- 敏感 API 识别：strcpy/strcat/sprintf/fread/memcpy... 调用点打标；
- 输入点分析：argv / 文件读 / stdin 的入口函数；
- 风险打分：按敏感 API 密度等给函数打 risk_score。

产出 analysis.json，schema 见 contract.py ANALYSIS_REQUIRED_KEYS。
"""
from __future__ import annotations


def analyze(target: str, workdir: str) -> dict:
    """分析 target，把结果写入 workdir/analysis.json 并返回该 dict。

    - 同时应产出初始种子与变异字典（配合 skill/seed_gen.py）；
    - 返回 dict 必须包含 contract.ANALYSIS_REQUIRED_KEYS 全部键。
    """
    raise NotImplementedError("P2 D2~D4 实现：capstone+pyelftools 静态分析")
