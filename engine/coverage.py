"""覆盖反馈模块 —— P3 负责（D2~D4）。

实现要点（计划书第二节）：
- 用 afl-clang-fast 插桩编译目标，afl-showmap 取单次运行边覆盖；
- 维护全局位图，对比判断 is_new；
- 解析退出状态区分 ok / crash / timeout。

接口契约见 contract.py（RunResult），签名不可改。
"""
from __future__ import annotations

from contract import RunResult


class CoverageRunner:
    """基于 afl-showmap 的覆盖反馈执行器（P1 主循环每轮调用）。"""

    def __init__(self, target: str, run_timeout_ms: int = 1000,
                 workdir: str = ".afl_tmp") -> None:
        self.target = target
        self.run_timeout_ms = run_timeout_ms
        self.workdir = workdir
        # P3 回填：目标静态总边数（objdump 反汇编总条件跳转边数，覆盖率口径统一用）
        self.total_edges: int = 0

    def run(self, input_data: bytes) -> RunResult:
        """以 input_data 为输入运行目标一次，返回覆盖与状态。"""
        raise NotImplementedError("P3 D2~D4 实现：afl-showmap 封装 + 全局位图对比")
