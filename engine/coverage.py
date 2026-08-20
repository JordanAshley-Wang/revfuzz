"""P3 —— 覆盖率收集（CoverageRunner）。

职责：
- 集成 afl-showmap，收集单次执行覆盖到的「边（edge）」集合
- 维护全局「已见边」集合，判断每次执行是否产生新覆盖（is_new）
- 结合 Executor 判定执行状态，组装 RunResult 交给 P1 的 fuzz 主循环

接口契约（P1 依赖，字段名不可随意改动）：
    class CoverageRunner:
        def run(self, input_data: bytes) -> RunResult: ...

    @dataclass
    class RunResult:
        edges: set[int]   # 本次覆盖到的边
        is_new: bool      # 是否产生新覆盖
        status: str       # "ok" | "crash" | "timeout"
        stderr: bytes     # ASan/UBSan 报错输出
        exec_ms: float    # 执行耗时（毫秒）
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field

from engine.executor import Executor, ExecutorConfig


@dataclass
class RunResult:
    edges: set[int]
    is_new: bool
    status: str
    stderr: bytes
    exec_ms: float
    # 额外字段（带默认值，不破坏 P1 契约；P5/P1 可按需读取）
    new_edges: set[int] = field(default_factory=set)
    exit_code: int | None = None


class CoverageRunner:
    """对外主接口：跑一次输入，返回带覆盖率的 RunResult。"""

    def __init__(
        self,
        target: str,
        timeout_ms: int = 1000,
        input_mode: str = "stdin",
        arg_template: list[str] | None = None,
        showmap_bin: str = "afl-showmap",
        coverage_mode: str = "auto",  # "auto" | "showmap" | "mock"
        env: dict[str, str] | None = None,
    ):
        self._executor = Executor(
            ExecutorConfig(
                target=target,
                timeout_ms=timeout_ms,
                input_mode=input_mode,
                arg_template=arg_template or [],
                env=env,
            )
        )
        self.showmap_bin = showmap_bin
        self.coverage_mode = coverage_mode
        self._showmap_available = shutil.which(showmap_bin) is not None
        self._seen_edges: set[int] = set()

    # ---- 全局覆盖率状态 ------------------------------------------------
    @property
    def total_edges(self) -> int:
        """累计已见边数量（P1 可用于打日志/评估覆盖率增长）。"""
        return len(self._seen_edges)

    def reset(self) -> None:
        """清空全局覆盖率（开始新一轮 campaign 前调用）。"""
        self._seen_edges.clear()

    # ---- 对外主入口 ----------------------------------------------------
    def run(self, input_data: bytes) -> RunResult:
        # 1) 覆盖率：收集本次覆盖到的边
        edges = self._collect_edges(input_data)

        # 2) 执行：判定 ok/crash/timeout，并抓 stderr（ASan 报错）
        exec_result = self._executor.run(input_data)

        # 3) 差集：判断是否产生新覆盖，并更新全局 bitmap
        new_edges = edges - self._seen_edges
        self._seen_edges.update(edges)

        return RunResult(
            edges=edges,
            is_new=bool(new_edges),
            status=exec_result.status,
            stderr=exec_result.stderr,
            exec_ms=exec_result.exec_ms,
            new_edges=new_edges,
            exit_code=exec_result.exit_code,
        )

    # ---- 覆盖率收集 ----------------------------------------------------
    def _collect_edges(self, input_data: bytes) -> set[int]:
        mode = self._resolve_mode()
        if mode == "mock":
            return self._mock_edges(input_data)
        return self._showmap_edges(input_data)

    def _resolve_mode(self) -> str:
        if self.coverage_mode != "auto":
            return self.coverage_mode
        return "showmap" if self._showmap_available else "mock"

    def _showmap_edges(self, input_data: bytes) -> set[int]:
        """用 afl-showmap 跑一次目标，解析 map 文件得到边集合。"""
        argv, stdin_data = self._executor.build_command(input_data)

        fd, map_path = tempfile.mkstemp(prefix="revfuzz_map_")
        os.close(fd)
        cmd = [self.showmap_bin, "-q", "-e", "-o", map_path, "--"] + argv
        try:
            subprocess.run(
                cmd,
                input=stdin_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._executor.config.timeout_ms / 1000.0,
                start_new_session=True,
            )
            edges = self._parse_map_file(map_path)
        except subprocess.TimeoutExpired:
            edges = set()
        finally:
            self._safe_remove(map_path)
        return edges

    @staticmethod
    def _parse_map_file(map_path: str) -> set[int]:
        """解析 afl-showmap 输出：每行 "<edge_id>:<count>"（edge_id 为十进制）。"""
        edges: set[int] = set()
        try:
            with open(map_path, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    edge_str = line.split(":", 1)[0].strip()
                    try:
                        edges.add(int(edge_str, 10))
                    except ValueError:
                        continue
        except FileNotFoundError:
            pass
        return edges

    @staticmethod
    def _mock_edges(input_data: bytes) -> set[int]:
        """本地无 afl 时的伪覆盖率：用输入哈希切出若干伪边，便于联调 is_new 逻辑。"""
        h = hashlib.sha256(input_data).digest()
        n = int.from_bytes(h[:4], "big")
        return {n & 0xFFFF, (n >> 8) & 0xFFFF, (n >> 16) & 0xFFFF}

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass
