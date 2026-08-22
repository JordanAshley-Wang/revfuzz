"""P3 —— 覆盖率收集（CoverageRunner）。

职责：
- 集成 afl-showmap，单次运行同时取得「边覆盖 + 执行状态 + stderr」
  （showmap 退出码：0=正常，2=目标崩溃或超时，配合输出中的 "timed out" 区分；
  目标 stderr 原样经 showmap 的 stderr 传出，ASan/UBSan 报告可直接解析）
- 维护全局「已见边」集合，判断每次执行是否产生新覆盖（is_new）
- 解析 showmap 报告的 Target map size（目标插桩边总数），供覆盖率分母兜底

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
import logging
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

from engine.executor import Executor, ExecutorConfig

LOG = logging.getLogger("revfuzz.coverage")

# showmap 连续空边集告警阈值：超过该次数仍无任何边，视为目标未插桩
_EMPTY_WARN_RUNS = 50

# showmap 输出中的插桩边总数（带 afl 运行时调试信息时打印）
_MAP_SIZE_RE = re.compile(rb"Target map size:\s*(\d+)")


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
        self._empty_runs = 0
        self._warned_empty = False
        #: showmap 报告的目标插桩边总数（首次运行解析得到，供 edges_total 兜底）
        self.static_map_size: int = 0

        # 关闭 ASan 外部符号化：ASan 崩溃时会 fork llvm-symbolizer 子进程，
        # 本机 llvm-symbolizer-13 与该 ASan 运行时（clang-14）不兼容，会死循环
        # 拖垮整机（实测单次崩溃从 0.04s 膨胀到 2m15s）。符号化由 P5 用
        # addr2line 兜底（triage._symbolize），不影响崩溃定位。
        env = dict(env or {})
        asan = env.get("ASAN_OPTIONS") or os.environ.get("ASAN_OPTIONS", "")
        if "symbolize" not in asan:
            asan = (asan + ":" if asan else "") + "symbolize=0"
        env["ASAN_OPTIONS"] = asan
        self._executor.config.env = env

        if self._resolve_mode() == "mock":
            LOG.warning("未找到 %s，覆盖率退化为 mock 伪边（仅供联调，"
                        "覆盖率数据不可信）", showmap_bin)

    # ---- 全局覆盖率状态 ------------------------------------------------
    @property
    def total_edges(self) -> int:
        """累计已见边数量（P1 可用于打日志/评估覆盖率增长）。"""
        return len(self._seen_edges)

    def reset(self) -> None:
        """清空全局覆盖率（开始新一轮 campaign 前调用）。"""
        self._seen_edges.clear()

    # ---- 对外主入口 ----------------------------------------------------
    def _resolve_mode(self) -> str:
        if self.coverage_mode != "auto":
            return self.coverage_mode
        return "showmap" if self._showmap_available else "mock"

    def run(self, input_data: bytes) -> RunResult:
        if self._resolve_mode() == "showmap":
            edges, status, stderr, exec_ms, exit_code = self._showmap_run(input_data)
            if exit_code == 1:
                # showmap 自身执行失败（如目标未插桩）：退化为 Executor 判状态
                exec_result = self._executor.run(input_data)
                status, stderr = exec_result.status, exec_result.stderr
                exec_ms, exit_code = exec_result.exec_ms, exec_result.exit_code
        else:
            edges = self._mock_edges(input_data)
            exec_result = self._executor.run(input_data)
            status, stderr = exec_result.status, exec_result.stderr
            exec_ms, exit_code = exec_result.exec_ms, exec_result.exit_code

        # 差集：判断是否产生新覆盖，并更新全局 bitmap
        new_edges = edges - self._seen_edges
        self._seen_edges.update(edges)

        # 插桩退化告警：showmap 长期取不到边，目标多半未用 afl 插桩编译
        if not self._seen_edges and self._resolve_mode() == "showmap":
            self._empty_runs += 1
            if self._empty_runs >= _EMPTY_WARN_RUNS and not self._warned_empty:
                LOG.warning("afl-showmap 连续 %d 次未取到任何边，目标可能未用 "
                            "afl-clang-fast/afl-gcc 插桩编译，覆盖引导将退化为盲 fuzz",
                            self._empty_runs)
                self._warned_empty = True

        return RunResult(
            edges=edges,
            is_new=bool(new_edges),
            status=status,
            stderr=stderr,
            exec_ms=exec_ms,
            new_edges=new_edges,
            exit_code=exit_code,
        )

    # ---- showmap 单次运行（覆盖 + 状态一次拿齐） ------------------------
    def _showmap_run(
        self, input_data: bytes
    ) -> tuple[set[int], str, bytes, float, int | None]:
        """afl-showmap 跑一次目标：解析 map 文件得边集合，退出码/输出判状态。

        退出码约定（实测 afl++ 4.00c，插桩目标）：
          0 = 正常退出（含目标以非 0 码正常退出）；
          2 = 目标崩溃（信号致死）或超时被杀 —— 用输出里的超时字样区分
              （4.00c 为 "timed off"，旧版为 "timed out"）；
          1 = showmap 自身失败（目标未插桩等），调用方退化走 Executor。
        目标的 stderr 由 showmap 原样转发到自己的 stderr，ASan/UBSan 报告在其中。
        """
        argv, stdin_data = self._executor.build_command(input_data)
        timeout_ms = self._executor.config.timeout_ms

        fd, map_path = tempfile.mkstemp(prefix="revfuzz_map_")
        os.close(fd)
        cmd = [self.showmap_bin, "-e", "-t", str(timeout_ms),
               "-o", map_path, "--"] + argv
        env = dict(os.environ)
        # 禁用 forkserver：高负载下 showmap 超时被杀时 forkserver 子进程会成孤儿
        # 堆积拖垮整机；单跑模式下禁用它代价很小（ASan 启动本身就是主要开销）
        env["AFL_NO_FORKSRV"] = "1"
        if self._executor.config.env:
            env.update(self._executor.config.env)
        start = time.perf_counter()
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,  # 新会话：超时后按进程组清理目标进程树
        )
        try:
            out, err = proc.communicate(
                input=stdin_data,
                timeout=timeout_ms / 1000.0 + 2.0,  # 给 showmap 留超时余量
            )
            exec_ms = (time.perf_counter() - start) * 1000.0
        except subprocess.TimeoutExpired:
            # subprocess 只杀直接子进程，showmap 的 forkserver/目标会成孤儿
            # 继续跑；这里杀掉整个进程组，避免僵尸目标堆积拖垮机器
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            proc.communicate()  # 收割
            self._safe_remove(map_path)
            return set(), "timeout", b"", float(timeout_ms), None
        finally:
            edges = self._parse_map_file(map_path)
            self._safe_remove(map_path)

        if not self.static_map_size:
            m = _MAP_SIZE_RE.search(out + err)
            if m:
                self.static_map_size = int(m.group(1))

        if proc.returncode == 0:
            status = "ok"
        elif proc.returncode == 2 and (
            # afl++ 4.00c 打印 "+++ Program timed off +++"，旧版为 "timed out"
            b"timed off" in (out + err) or b"timed out" in (out + err)
        ):
            status = "timeout"
        elif proc.returncode == 1:
            status = "ok"  # 占位：rc=1 由调用方退化走 Executor 重判
        else:
            status = "crash"
        return edges, status, err, exec_ms, proc.returncode

    # ---- 覆盖率收集（mock 用） ------------------------------------------
    @staticmethod
    def _mock_edges(input_data: bytes) -> set[int]:
        """本地无 afl 时的伪覆盖率：用输入哈希切出若干伪边，便于联调 is_new 逻辑。"""
        h = hashlib.sha256(input_data).digest()
        n = int.from_bytes(h[:4], "big")
        return {n & 0xFFFF, (n >> 8) & 0xFFFF, (n >> 16) & 0xFFFF}

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
    def _safe_remove(path: str) -> None:
        try:
            os.remove(path)
        except OSError:
            pass
