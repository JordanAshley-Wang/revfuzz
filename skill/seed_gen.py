"""逆向 Skill：种子 / 字典生成 —— P2 负责（D3~D4）。

基于静态分析结果生成：
- 初始种子集：尽量触达高风险函数的输入（验收覆盖率的关键）；
- 变异字典：提取的字符串、magic bytes、格式关键字。

接口契约见 contract.py，签名不可改。
"""
from __future__ import annotations


def generate_seeds(analysis: dict, corpus_dir: str) -> list[str]:
    """按 analysis 在 corpus_dir 下生成初始种子文件，返回路径列表。"""
    raise NotImplementedError("P2 D3 实现：初始种子生成")


def generate_dictionary(analysis: dict) -> list[bytes]:
    """从 analysis 提取变异字典（字符串/magic bytes）。"""
    raise NotImplementedError("P2 D4 实现：变异字典生成")
