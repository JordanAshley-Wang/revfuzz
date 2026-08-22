"""崩溃分类 / 去重 / 最小化 —— P5 负责（D2~D4）。

解析 ASan / UBSan 的 stderr 输出，产出结构化 CrashInfo：
- heap-buffer-overflow / stack-buffer-overflow / heap-use-after-free：ASan 报告；
- integer-overflow：UBSan "runtime error: signed integer overflow" 等；
- 无法识别归入 unknown。

接口契约见 contract.py（CrashInfo），签名不可改：
    classify_crash(stderr: bytes, input_path: str) -> CrashInfo

补充函数（不属固定契约，供 P1 主循环 / 测试调用）：
    minimize_crash(target, input_path, ...) -> str   # 崩溃最小化，返回最小化输入路径
    deduplicate(crashes) -> list[CrashInfo]          # 按 dedup_key 去重

约定：不做 MSan，只交 ASan + UBSan（计划书风险预案）。
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from contract import CrashInfo, VulnType


def _run_env() -> dict:
    """执行目标的环境：关闭 ASan 外部符号化。

    ASan 崩溃时默认 fork llvm-symbolizer 做符号化；本机 llvm-symbolizer-13
    与 clang-14 的 ASan 运行时不兼容会死循环拖垮整机。符号化由本模块
    _symbolize()（addr2line）兜底，无需 ASan 外部符号器。
    """
    env = dict(os.environ)
    asan = env.get("ASAN_OPTIONS", "")
    if "symbolize" not in asan:
        env["ASAN_OPTIONS"] = (asan + ":" if asan else "") + "symbolize=0"
    return env

# ============================================================
# 分类规则（正则 + 映射表）
# ============================================================

# ASan 错误行： "==123==ERROR: AddressSanitizer: heap-buffer-overflow on address ..."
_ASAN_ERROR_RE = re.compile(r"ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9_-]+)")

# UBSan 错误行： "file.c:12:5: runtime error: signed integer overflow: ..."
_UBSAN_ERROR_RE = re.compile(r"runtime error:\s*([^:\n]+?)(?::|\n)")

# ASan 报告类型 -> 题目要求的 vuln_type（只保留 4 类 + unknown）
_ASAN_TO_VULN = {
    "heap-buffer-overflow": "heap-buffer-overflow",
    "stack-buffer-overflow": "stack-buffer-overflow",
    "heap-use-after-free": "heap-use-after-free",
    # 常见变体归到最接近的类
    "stack-use-after-return": "stack-buffer-overflow",
    "stack-use-after-scope": "stack-buffer-overflow",
    "stack-overflow": "stack-buffer-overflow",
    "global-buffer-overflow": "unknown",
    "double-free": "unknown",
    "segv": "unknown",
    "use-after-poison": "unknown",
}

# UBSan 报告短语 -> 题目要求的 vuln_type
_UBSAN_TO_VULN = {
    "signed integer overflow": "integer-overflow",
    "unsigned integer overflow": "integer-overflow",
    "integer overflow": "integer-overflow",
    "shift exponent": "integer-overflow",  # 移位溢出，同属整数类
}


def _classify_vuln_type(stderr: bytes) -> VulnType:
    """从 stderr 里识别漏洞类型，返回 5 种之一。ASan 优先，其次 UBSan。"""
    text = stderr.decode("utf-8", errors="replace")

    m = _ASAN_ERROR_RE.search(text)
    if m:
        return _ASAN_TO_VULN.get(m.group(1), "unknown")

    for m in _UBSAN_ERROR_RE.finditer(text):
        phrase = m.group(1).strip().lower()
        for key, vuln in _UBSAN_TO_VULN.items():
            if key in phrase:
                return vuln

    return "unknown"


# ============================================================
# 位置提取
# ============================================================

# ASan 栈帧： "    #0 0x4007d4 in main /path/vuln_heap.c:12:15"
_ASAN_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s*(.*)$")

# ASan SUMMARY 行： "SUMMARY: AddressSanitizer: heap-buffer-overflow /p/vuln_heap.c:12:15 in main"
_ASAN_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*AddressSanitizer:\s*\S+\s+(.+?:\d+)(?::\d+)?\s+in\s+(\S+)"
)

# 未符号化的 ASan SUMMARY 行： "SUMMARY: AddressSanitizer: xxx (/p/bin+0x487b97)"
_ASAN_OFFSET_SUMMARY_RE = re.compile(
    r"SUMMARY:\s*AddressSanitizer:\s*\S+\s+\((\S+?)\+0x([0-9a-fA-F]+)\)"
)

# 未符号化的栈帧： "#1 0x4ce494  (/p/bin+0x4ce494)"（SUMMARY 指向拦截器时用帧兜底）
_ASAN_OFFSET_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+\((\S+?)\+0x([0-9a-fA-F]+)\)"
)


def _symbolize(binary: str, addr_hex: str) -> tuple[str, str]:
    """用 addr2line 把 (binary+0xADDR) 还原成 (函数, 文件:行)；失败返回 ("","")。

    ASan 找不到 llvm-symbolizer 时栈帧只给裸偏移，靠这个兜底补符号。
    """
    try:
        proc = subprocess.run(
            ["addr2line", "-e", binary, "-f", "-C", "0x" + addr_hex],
            capture_output=True, text=True, timeout=5,
        )
        lines = proc.stdout.splitlines()
        if len(lines) >= 2 and "??" not in lines[1]:
            return lines[0].strip(), lines[1].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return "", ""

# UBSan 错误行自带位置： "vuln_int.c:12:5: runtime error: ..."
_UBSAN_LOC_RE = re.compile(r"^(.+?:\d+:\d+):\s*runtime error:", re.MULTILINE)


def _norm_path(p: str) -> str:
    """归一化位置：去掉目录、去掉列号，只留 basename:行号。

    保证同一个崩溃不管走 SUMMARY 行还是栈帧兜底，都得到一致的去重键。
    """
    p = p.strip()
    p = re.sub(r"^.*[/\\]", "", p)          # 去目录
    p = re.sub(r"(:\d+):\d+$", r"\1", p)    # 去列号，保留 file:line
    return p


def _extract_location(stderr: bytes, vuln_type: str) -> str:
    """提取崩溃位置，统一成 "函数 文件:行" 或 "文件:行" 的短形式。"""
    text = stderr.decode("utf-8", errors="replace")

    # UBSan：错误行自带 file:line:col
    if vuln_type == "integer-overflow":
        m = _UBSAN_LOC_RE.search(text)
        if m:
            return _norm_path(m.group(1))

    # ASan：优先 SUMMARY 行
    m = _ASAN_SUMMARY_RE.search(text)
    if m:
        return f"{m.group(2)} {_norm_path(m.group(1))}".strip()

    # ASan 未符号化（裸偏移）：SUMMARY 常指向 __interceptor_*（无行号），
    # 需遍历栈帧取第一个能符号化出 文件:行 的用户帧
    if _ASAN_OFFSET_SUMMARY_RE.search(text):
        for fm in _ASAN_OFFSET_FRAME_RE.finditer(text):
            func, fileline = _symbolize(fm.group(1), fm.group(2))
            if fileline:
                return f"{func} {_norm_path(fileline)}".strip()

    # 否则取第一个带函数名 + 文件:行的栈帧（通常是 #0）
    for line in text.splitlines():
        fm = _ASAN_FRAME_RE.search(line)
        if fm:
            func = fm.group(1)
            rest = fm.group(2).strip()
            fileloc = re.search(r"(\S+?:\d+(?::\d+)?)", rest)
            loc = fileloc.group(1) if fileloc else rest
            return f"{func} {_norm_path(loc)}".strip()

    return "unknown"


# ============================================================
# 去重键
# ============================================================

def _make_dedup_key(vuln_type: str, location: str) -> str:
    """去重键 = vuln_type + 顶层栈帧（归一化后），同一成因的崩溃归并。"""
    return f"{vuln_type}:{location}"


# ============================================================
# 复现命令
# ============================================================

def _build_repro_cmd(input_path: str) -> str:
    """生成复现命令。classify_crash 拿不到 target，用 <target> 占位。

    目标程序（P7 靶标）均支持 stdin，`< input` 重定向是通用喂入方式。
    报告模块（P6）可按 CampaignStats.target 替换占位符。
    """
    return f"./<target> < {input_path}"


def make_repro_cmd(target: str, input_path: str, feed_mode: str = "stdin") -> str:
    """已知 target 时生成完整复现命令（供 minimize_crash / 测试用）。"""
    if feed_mode == "file":
        return f"{target} {input_path}"
    return f"{target} < {input_path}"


# ============================================================
# 主接口：崩溃分类（契约固定签名，勿改）
# ============================================================

def classify_crash(stderr: bytes, input_path: str) -> CrashInfo:
    """解析一次崩溃，返回分类结果。

    参数：
      stderr     —— 目标程序崩溃时的 stderr（ASan/UBSan 报告文本）
      input_path —— 触发崩溃的输入文件路径

    minimized_input 置 None：最小化需要反复重跑 target，本函数拿不到 target，
    真正的缩减用 minimize_crash() 单独完成。
    """
    vuln_type = _classify_vuln_type(stderr)
    location = _extract_location(stderr, vuln_type)
    dedup_key = _make_dedup_key(vuln_type, location)

    return CrashInfo(
        vuln_type=vuln_type,
        location=location,
        dedup_key=dedup_key,
        input_path=input_path,
        minimized_input=None,
        repro_cmd=_build_repro_cmd(input_path),
        raw_stderr=stderr,
    )


# ============================================================
# 崩溃去重（主循环已按 dedup_key 去重，此函数供测试/独立使用）
# ============================================================

def deduplicate(crashes: List[CrashInfo]) -> List[CrashInfo]:
    """按 dedup_key 去重，每个 key 只保留第一个崩溃。"""
    seen = {}
    for c in crashes:
        seen.setdefault(c.dedup_key, c)
    return list(seen.values())


# ============================================================
# 崩溃最小化（简化版 delta-debugging / ddmin）
# ============================================================

def _run_target(
    target: str,
    data: bytes,
    vuln_type: Optional[str],
    timeout: float,
    feed_mode: str,
) -> bool:
    """重跑目标，判断给定输入是否仍触发「同一类」崩溃。

    崩溃判定不只看出错码——UBSan 默认只打印不退出，所以要检查 stderr 签名。
    """
    try:
        if feed_mode == "stdin":
            proc = subprocess.run(
                [target], input=data, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=timeout, env=_run_env(),
            )
        else:
            fd, tmp = tempfile.mkstemp()
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            try:
                proc = subprocess.run(
                    [target, tmp], stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, timeout=timeout, env=_run_env(),
                )
            finally:
                os.unlink(tmp)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

    if vuln_type is not None:
        return _classify_vuln_type(proc.stderr) == vuln_type

    return (
        proc.returncode != 0
        or b"ERROR: AddressSanitizer" in proc.stderr
        or b"runtime error:" in proc.stderr
    )


def _stderr_of(target: str, data: bytes, timeout: float, feed_mode: str) -> bytes:
    """只取一次运行的 stderr（供自动探测类型用）。"""
    try:
        if feed_mode == "stdin":
            proc = subprocess.run(
                [target], input=data, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=timeout, env=_run_env(),
            )
        else:
            fd, tmp = tempfile.mkstemp()
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
            try:
                proc = subprocess.run(
                    [target, tmp], stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, timeout=timeout, env=_run_env(),
                )
            finally:
                os.unlink(tmp)
        return proc.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return b""


def minimize_crash(
    target: str,
    input_path: str,
    vuln_type: Optional[str] = None,
    feed_mode: str = "stdin",
    timeout: float = 2.0,
    max_iters: int = 500,
) -> str:
    """对触发崩溃的输入做简化版 ddmin，尽量缩小输入。

    返回最小化后的输入【路径】（写为 input_path + ".min"），符合
    CrashInfo.minimized_input 的 str|None 约定。

    vuln_type 建议由 classify_crash() 先得到再传入；若为 None 会自动探测一次。
    """
    data = Path(input_path).read_bytes()

    if vuln_type is None:
        vuln_type = _classify_vuln_type(_stderr_of(target, data, timeout, feed_mode))

    n = 2  # ddmin 初始分块数
    iters = 0
    while len(data) >= 2 and iters < max_iters:
        chunk = max(1, len(data) // n)
        reduced = False
        for i in range(0, len(data), chunk):
            candidate = data[:i] + data[i + chunk:]
            if not candidate:
                continue
            iters += 1
            if _run_target(target, candidate, vuln_type, timeout, feed_mode):
                data = candidate
                n = max(2, n - 1)  # 减小粒度重新精化
                reduced = True
                break
        if not reduced:
            if n >= len(data):
                break
            n = min(n * 2, len(data))

    out_path = input_path + ".min"
    Path(out_path).write_bytes(data)
    return out_path


# ============================================================
# 自测：在仓库根目录下 python -m engine.triage 可验证分类逻辑
# ============================================================

if __name__ == "__main__":
    samples = {
        "heap": b"""=================================================================
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014 at pc 0x4007d5
READ of size 4 at 0x602000000014 thread T0
    #0 0x4007d4 in main /home/jzk/revfuzz/targets/vuln_heap.c:12:15
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/jzk/revfuzz/targets/vuln_heap.c:12:15 in main
""",
        "stack": b"""=================================================================
==1234==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffc12345678
    #0 0x4007d4 in main /home/jzk/revfuzz/targets/vuln_stack.c:9:10
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/jzk/revfuzz/targets/vuln_stack.c:9:10 in main
""",
        "uaf": b"""=================================================================
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
    #0 0x4007d4 in main /home/jzk/revfuzz/targets/vuln_uaf.c:15:5
SUMMARY: AddressSanitizer: heap-use-after-free /home/jzk/revfuzz/targets/vuln_uaf.c:15:5 in main
""",
        "int": b"""vuln_int.c:38:14: runtime error: signed integer overflow: 536870912 * 4 cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior vuln_int.c:38:14 in
""",
    }

    for name, err in samples.items():
        info = classify_crash(err, f"/tmp/crash_{name}")
        print(f"{name:6} -> {info}")
