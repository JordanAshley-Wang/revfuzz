"""P3 —— 目标程序执行器（Executor）。

职责：
- 以三种输入方式（argv / file / stdin）把测试用例喂给目标二进制
- 用 subprocess 运行目标，带超时控制
- 判定单次执行结果：正常退出(ok) / 崩溃(crash) / 超时(timeout)
- 捕获 stderr（ASan/UBSan 报错信息），供 P5 的 triage 分类

说明：
- 本模块只负责「跑起来 + 判状态」，不负责覆盖率；覆盖率由 coverage.py 通过
  afl-showmap 收集后与本模块结果合并。
- 生产环境为 WSL2 Ubuntu 24.04；本模块在 Windows 上也可运行（崩溃信号判定
  略有差异），便于本地 mock 目标联调。
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field

# 执行状态（与 coverage.RunResult.status 的取值保持一致）
STATUS_OK = "ok"
STATUS_CRASH = "crash"
STATUS_TIMEOUT = "timeout"

# 判定为「崩溃」的信号集合（跨平台：Windows 上部分信号不存在，用 getattr 兜底）
CRASH_SIGNALS = {
    getattr(signal, name)
    for name in ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE", "SIGSYS")
    if hasattr(signal, name)
}

# stderr 中出现这些标记即认为是 sanitizer 报错。
# 用于覆盖「不通过信号退出但仍报错」的情况（如 UBSan 的 recover 模式）。
SANITIZER_MARKERS = (
    b"AddressSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"runtime error:",
    b"heap-buffer-overflow",
    b"stack-buffer-overflow",
    b"heap-use-after-free",
    b"integer-overflow",
    b"SEGV on unknown address",
)


@dataclass
class ExecutorConfig:
    """执行器配置。

    target        目标二进制路径（或可执行脚本）
    timeout_ms    单次执行超时（毫秒），超时判为 timeout
    input_mode    输入方式：argv（命令行参数）/ file（临时文件）/ stdin（标准输入）
    arg_template  传给目标的参数模板；其中 "@@" 会被替换为：
                  - file 模式：临时输入文件路径
                  - argv 模式：输入字符串本身
                  若不含 "@@"：
                  - argv 模式：输入作为最后一个参数追加
                  - file 模式：写临时文件后把路径追加到末尾
                  - stdin 模式：输入走 stdin，arg_template 原样传参
    env           额外环境变量（合并到 os.environ，可用于 ASAN_OPTIONS 等）
    workdir       工作目录（None = 当前目录）
    """

    target: str
    timeout_ms: int = 1000
    input_mode: str = "stdin"
    arg_template: list[str] = field(default_factory=list)
    env: dict[str, str] | None = None
    workdir: str | None = None


@dataclass
class ExecutorResult:
    """单次执行结果（原始信息，尚未做覆盖率差集）。"""

    status: str            # "ok" | "crash" | "timeout"
    exit_code: int | None  # 退出码；被信号杀死时 returncode 为负
    signal: int | None     # 崩溃信号（无则 None）
    stdout: bytes
    stderr: bytes          # ASan/UBSan 报错信息在这里
    exec_ms: float         # 实际执行耗时（毫秒）


class Executor:
    """运行目标二进制并判定执行结果。"""

    def __init__(self, config: ExecutorConfig):
        self.config = config
        self._tmpfile: str | None = None  # file 模式复用的临时输入文件

    # ---- 对外主入口 -----------------------------------------------------
    def run(self, input_data: bytes) -> ExecutorResult:
        """执行一次目标，返回 ExecutorResult。"""
        argv, stdin_data = self.build_command(input_data)

        start = time.perf_counter()
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._merged_env(),
            cwd=self.config.workdir,
            start_new_session=True,  # POSIX 下新会话，便于超时后按进程组清理
        )
        try:
            stdout, stderr = proc.communicate(
                input=stdin_data, timeout=self.config.timeout_ms / 1000.0
            )
            exec_ms = (time.perf_counter() - start) * 1000.0
        except subprocess.TimeoutExpired:
            self._kill_process_tree(proc)
            proc.communicate()  # 收割，避免僵尸进程
            return ExecutorResult(
                status=STATUS_TIMEOUT,
                exit_code=None,
                signal=None,
                stdout=b"",
                stderr=b"",
                exec_ms=float(self.config.timeout_ms),
            )

        return self._classify(proc.returncode, stdout, stderr, exec_ms)

    # ---- 命令构造 ------------------------------------------------------
    def build_command(self, input_data: bytes) -> tuple[list[str], bytes | None]:
        """根据 input_mode 构造 (argv, stdin_data)；stdin_data 为 None 表示不从 stdin 输入。"""
        argv = [self.config.target]
        mode = self.config.input_mode
        has_placeholder = "@@" in self.config.arg_template

        if mode == "file":
            input_path = self._write_temp_input(input_data)
            argv += [input_path if a == "@@" else a for a in self.config.arg_template]
            if not has_placeholder:
                argv.append(input_path)
            return argv, None

        if mode == "argv":
            # argv 只能承载字符串，用 latin-1 做 1:1 字节映射（含 NUL 的二进制无法可靠传递）
            arg = input_data.decode("latin-1")
            argv += [arg if a == "@@" else a for a in self.config.arg_template]
            if not has_placeholder:
                argv.append(arg)
            return argv, None

        if mode == "stdin":
            argv += list(self.config.arg_template)
            return argv, input_data

        raise ValueError(f"unknown input_mode: {mode!r}")

    # ---- 内部辅助 ------------------------------------------------------
    def _classify(
        self, returncode: int | None, stdout: bytes, stderr: bytes, exec_ms: float
    ) -> ExecutorResult:
        status = STATUS_OK
        sig: int | None = None

        if returncode is not None and returncode < 0:
            # 被信号杀死（如 SIGSEGV/SIGABRT）=> 崩溃
            sig = -returncode
            status = STATUS_CRASH
        elif self._is_sanitizer_error(stderr):
            # 进程正常退出但仍打印了 sanitizer 报错（如 UBSan recover 模式）=> 崩溃
            status = STATUS_CRASH

        return ExecutorResult(
            status=status,
            exit_code=returncode,
            signal=sig,
            stdout=stdout,
            stderr=stderr,
            exec_ms=exec_ms,
        )

    @staticmethod
    def _is_sanitizer_error(stderr: bytes) -> bool:
        return any(marker in stderr for marker in SANITIZER_MARKERS)

    def _write_temp_input(self, input_data: bytes) -> str:
        """把输入写到（复用的）临时文件，返回文件路径。"""
        if self._tmpfile is None:
            fd, self._tmpfile = tempfile.mkstemp(prefix="revfuzz_", suffix=".in")
            os.close(fd)
        with open(self._tmpfile, "wb") as f:
            f.write(input_data)
        return self._tmpfile

    def _merged_env(self) -> dict[str, str] | None:
        if not self.config.env:
            return None
        env = dict(os.environ)
        env.update(self.config.env)
        return env

    @staticmethod
    def _kill_process_tree(proc: subprocess.Popen) -> None:
        """超时后清理整个进程树（目标是 fork 出子进程时也一并杀掉）。"""
        try:
            if os.name == "nt":
                # Windows 简化处理；如需杀整棵树可改用 taskkill /T /F
                proc.kill()
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    def close(self) -> None:
        """释放临时文件（file 模式下）。"""
        if self._tmpfile is not None:
            try:
                os.remove(self._tmpfile)
            except OSError:
                pass
            self._tmpfile = None
