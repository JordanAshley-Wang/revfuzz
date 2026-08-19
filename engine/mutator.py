"""变异器 —— P4 负责（D2~D4）。

必须实现 4 种变异策略（功能要求 #2）：
位翻转 / 算术变异 / 字典替换 / Havoc 模式（堆叠多轮随机变异）。

接口契约见 contract.py，签名不可改。
"""
from __future__ import annotations


def mutate(seed: bytes, dictionary: list[bytes], max_len: int) -> bytes:
    """对 seed 做一次变异，返回长度不超过 max_len 的新输入。

    - dictionary 来自 P2 静态分析（字符串/magic bytes），可为空；
    - 策略选择可由 P4 自定（如按概率调度 4 种策略）。
    """
    raise NotImplementedError("P4 D2~D4 实现：位翻转/算术/字典/Havoc")
