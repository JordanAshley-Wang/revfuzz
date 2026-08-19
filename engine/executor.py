"""目标执行器 —— P3 负责（D2~D4）。

直接运行目标程序并捕获 stderr，供两处使用：
- CoverageRunner 内部（afl-showmap 之外的普通执行）；
- P5 triage 复现崩溃 / 最小化输入时反复执行目标。
"""
from __future__ import annotations


class Executor:
    """带超时控制的目标进程执行器。"""

    def __init__(self, target: str, run_timeout_ms: int = 1000,
                 env: dict | None = None) -> None:
        self.target = target
        self.run_timeout_ms = run_timeout_ms
        self.env = env

    def execute(self, input_data: bytes) -> tuple[int, bytes, float]:
        """运行一次目标，返回 (exit_code, stderr, exec_ms)。

        超时以 exit_code=-9 或约定值返回，stderr 保留已捕获输出。
        """
        raise NotImplementedError("P3 D2~D4 实现：subprocess 执行 + 超时回收")
