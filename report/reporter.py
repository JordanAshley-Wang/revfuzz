"""RevFuzz 报告生成 —— P6。

按 contract.py 定义的数据结构生成 JSON / Markdown 双格式报告：

    generate_report(campaign_stats: CampaignStats, crashes: list[CrashInfo],
                    analysis: dict | None, fmt: str, out_dir: str = "out") -> None

- fmt ∈ {"json", "markdown"}，分别输出 out_dir/report.json、out_dir/report.md；
- analysis 可为 None（无静态分析模式），报告降级展示；
- report.json 顶层包含验收指标字段 unique_crashes / edges_covered /
  edges_total / total_execs / timeouts，与 tests/acceptance.sh 解析口径一致。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from contract import CampaignStats, CrashInfo

logger = logging.getLogger("revfuzz.reporter")

_SUPPORTED_FORMATS = ("json", "markdown")

# analysis 缺失字段的兜底默认值（P2 schema 见 contract.ANALYSIS_REQUIRED_KEYS）
_DEFAULT_ANALYSIS: dict[str, Any] = {
    "target": "",
    "functions": [],
    "dangerous_calls": [],
    "input_points": [],
    "dictionary": [],
    "seeds": [],
}


def generate_report(
    campaign_stats: CampaignStats,
    crashes: list[CrashInfo],
    analysis: dict | None,
    fmt: str,
    out_dir: str = "out",
) -> None:
    """生成 fuzz 测试报告。

    Args:
        campaign_stats: 一次 fuzzing 活动的汇总统计（P1 构造的 CampaignStats）。
        crashes: 去重后的可复现崩溃列表（P5 产出的 CrashInfo）。
        analysis: 静态分析结果（P2 产出 dict），可为 None 表示无分析模式。
        fmt: 输出格式，仅支持 "json" / "markdown"。
        out_dir: 输出目录，不存在会自动创建。

    Raises:
        ValueError: fmt 不是 "json" / "markdown" 时抛出。
    """
    if fmt not in _SUPPORTED_FORMATS:
        raise ValueError(f"不支持的报告格式: {fmt!r}，仅支持 {list(_SUPPORTED_FORMATS)}")

    data = _build_report_data(campaign_stats, crashes, analysis)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        path = out / "report.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=_json_default)
    else:  # markdown
        path = out / "report.md"
        path.write_text(_render_markdown(data), encoding="utf-8")

    logger.info("已生成 %s 报告: %s", fmt, path)


# ======================================================================
# 内部实现
# ======================================================================

def _build_report_data(
    stats: CampaignStats,
    crashes: list[CrashInfo],
    analysis: dict | None,
) -> dict:
    """把契约输入归一化为统一的报告数据 dict。

    覆盖率口径与 P3 对齐：edges_covered / edges_total * 100%。
    稳定性口径：非超时执行 / 总执行 * 100%（(total_execs - timeouts) / total_execs）。
    """
    cov_pct = round(stats.edges_covered / stats.edges_total * 100.0, 2) if stats.edges_total > 0 else 0.0
    stab_pct = (
        round((stats.total_execs - stats.timeouts) / stats.total_execs * 100.0, 2)
        if stats.total_execs > 0
        else 0.0
    )
    start_text = (
        datetime.fromtimestamp(stats.start_time).strftime("%Y-%m-%d %H:%M:%S")
        if stats.start_time
        else ""
    )

    return {
        # ===== 顶层验收指标（acceptance.sh 解析字段） =====
        "unique_crashes": stats.unique_crashes,
        "edges_covered": stats.edges_covered,
        "edges_total": stats.edges_total,
        "total_execs": stats.total_execs,
        "timeouts": stats.timeouts,
        # ===== 可读性附加指标 =====
        "code_coverage": cov_pct,
        "runtime_stability": stab_pct,
        # ===== 运行概况 =====
        "crashes_total": stats.crashes,      # 崩溃总数（含重复）
        "execs_per_sec": stats.execs_per_sec,
        "corpus_size": stats.corpus_size,
        # ===== 基本信息 =====
        "basic_info": {
            "target": stats.target,
            "start_time": start_text,
            "elapsed_s": stats.elapsed_s,
        },
        # ===== 崩溃列表（每个 CrashInfo 全字段） =====
        "crash_details": [_crash_to_dict(c) for c in crashes],
        # ===== 逆向分析结果（无分析模式降级为默认值） =====
        "reverse_analysis": _analysis_to_dict(analysis),
    }


def _crash_to_dict(crash: CrashInfo) -> dict:
    """CrashInfo -> dict（raw_stderr 为 bytes，JSON 序列化时由 _json_default 处理）。"""
    return {
        "vuln_type": crash.vuln_type,
        "location": crash.location,
        "dedup_key": crash.dedup_key,
        "input_path": crash.input_path,
        "minimized_input": crash.minimized_input,
        "repro_cmd": crash.repro_cmd,
        "raw_stderr": crash.raw_stderr,
    }


def _analysis_to_dict(analysis: dict | None) -> dict:
    """analysis 归一化：None 或缺字段时用默认值填充，保证不崩溃。"""
    if not isinstance(analysis, dict):
        return dict(_DEFAULT_ANALYSIS)
    return {key: analysis.get(key, default) for key, default in _DEFAULT_ANALYSIS.items()}


def _json_default(obj: Any) -> Any:
    """JSON 序列化兜底：bytes 转可读文本，避免 TypeError。"""
    if isinstance(obj, bytes):
        return _display(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _display(value: Any) -> str:
    """把任意值转成可展示文本（bytes 解码失败时转 hex）。"""
    if value is None:
        return ""
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - 兜底保证不崩溃
            return value.hex()
    return str(value)


def _escape_inline(value: Any) -> str:
    """转义 Markdown 内联代码里的反引号与表格管道符。"""
    return _display(value).replace("`", "\\`").replace("|", "\\|")


# ======================================================================
# Markdown 渲染
# ======================================================================

def _render_markdown(data: dict) -> str:
    """把统一报告数据渲染为 Markdown 文本。"""
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    basic = data["basic_info"]
    crashes = data["crash_details"]
    analysis = data["reverse_analysis"]

    lines: list[str] = []

    # ---- 顶部大标题 + 生成时间 ----
    lines.append("# RevFuzz 模糊测试报告\n")
    lines.append(f"> 生成时间：{gen_time}\n")

    # ---- 目录导航 ----
    lines.append("## 目录\n")
    for anchor, title in (
        ("metrics", "验收指标"),
        ("basic", "基本信息"),
        ("coverage", "覆盖率统计"),
        ("crashes", "崩溃列表"),
        ("analysis", "逆向分析结果"),
        ("runstats", "运行统计"),
    ):
        lines.append(f"- [{title}](#{anchor})")
    lines.append("")

    # ---- 验收指标高亮表格（置顶，第一观感） ----
    lines.append('## <a id="metrics"></a>验收指标\n')
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 可复现崩溃数 `unique_crashes` | **{data['unique_crashes']}** |")
    lines.append(f"| 代码覆盖率 `code_coverage` | **{data['code_coverage']}%** |")
    lines.append(f"| 运行稳定性 `runtime_stability` | **{data['runtime_stability']}%** |\n")

    # ---- 基本信息 ----
    lines.append('## <a id="basic"></a>基本信息\n')
    lines.append("| 项目 | 内容 |")
    lines.append("| --- | --- |")
    lines.append(f"| 目标程序 | `{_escape_inline(basic['target'])}` |")
    lines.append(f"| 开始时间 | {basic['start_time']} |")
    lines.append(f"| 运行时长 | {basic['elapsed_s']} s |\n")

    # ---- 覆盖率统计 ----
    lines.append('## <a id="coverage"></a>覆盖率统计\n')
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 总条件跳转边数 | {data['edges_total']} |")
    lines.append(f"| 已命中边数 | {data['edges_covered']} |")
    lines.append(f"| 覆盖率 | **{data['code_coverage']}%** |\n")

    # ---- 崩溃列表 ----
    lines.append('## <a id="crashes"></a>崩溃列表\n')
    if not crashes:
        lines.append("> 本轮 fuzz 未产生可复现崩溃。\n")
    else:
        lines.append(f"共发现 **{len(crashes)}** 个可复现崩溃。\n")
        lines.append("| # | 漏洞类型 | 位置 | 复现命令 |")
        lines.append("| --- | --- | --- | --- |")
        for i, crash in enumerate(crashes, 1):
            cmd = _escape_inline(crash["repro_cmd"]).replace("\n", " ")
            lines.append(
                f"| {i} | {crash['vuln_type']} | "
                f"`{_escape_inline(crash['location'])}` | `{cmd}` |"
            )
        lines.append("")

        for i, crash in enumerate(crashes, 1):
            lines.append(f"### 崩溃详情 #{i}（{crash['vuln_type']}）\n")
            lines.append(f"- **漏洞类型**：`{crash['vuln_type']}`")
            lines.append(f"- **位置**：`{_escape_inline(crash['location'])}`")
            lines.append(f"- **去重键**：`{_escape_inline(crash['dedup_key'])}`")
            lines.append(f"- **输入文件**：`{_escape_inline(crash['input_path'])}`")
            lines.append(f"- **最小化输入**：`{_escape_inline(crash['minimized_input']) or '(未最小化)'}`")
            lines.append(f"- **复现命令**：`{_escape_inline(crash['repro_cmd'])}`")
            stderr = _display(crash["raw_stderr"]).strip()
            if stderr:
                lines.append("- **ASan/UBSan 原始输出**：\n")
                lines.append("```")
                lines.append(stderr[:2000])
                lines.append("```")
            lines.append("")

    # ---- 逆向分析结果（可为 None，降级展示） ----
    lines.append('## <a id="analysis"></a>逆向分析结果\n')
    lines.append(f"- **目标程序**：`{_escape_inline(analysis.get('target', ''))}`")

    functions = analysis.get("functions", []) or []
    lines.append("\n### 函数清单\n")
    if not functions:
        lines.append("> 无函数信息（静态分析未启用或未产出）。")
    else:
        lines.append("| 函数 | 地址 | 大小 | 风险分 | 危险调用 |")
        lines.append("| --- | --- | --- | --- | --- |")
        for fn in functions:
            calls = ", ".join(_escape_inline(c) for c in _get(fn, "calls", []) or []) or "-"
            lines.append(
                f"| `{_escape_inline(_get(fn, 'name', ''))}` | 0x{int(_get(fn, 'addr', 0)):x} | "
                f"{_get(fn, 'size', 0)} | **{_get(fn, 'risk_score', 0)}** | {calls} |"
            )
        lines.append("")

    dangerous_calls = analysis.get("dangerous_calls", []) or []
    lines.append("### 危险调用（敏感 API）\n")
    if not dangerous_calls:
        lines.append("> 未检测到高危调用。")
    else:
        lines.append("| 所属函数 | API | 地址 | 风险等级 |")
        lines.append("| --- | --- | --- | --- |")
        for call in dangerous_calls:
            risk = str(_get(call, "risk", ""))
            tag = f"**{risk}**" if risk.lower() == "high" else risk
            lines.append(
                f"| `{_escape_inline(_get(call, 'function', ''))}` | "
                f"`{_escape_inline(_get(call, 'api', ''))}` | "
                f"0x{int(_get(call, 'addr', 0)):x} | {tag} |"
            )
        lines.append("")

    input_points = analysis.get("input_points", []) or []
    lines.append("### 输入点\n")
    if not input_points:
        lines.append("> 未识别到输入点。")
    else:
        lines.append("| 输入类型 | 所在函数 |")
        lines.append("| --- | --- |")
        for point in input_points:
            lines.append(
                f"| `{_escape_inline(_get(point, 'type', ''))}` | "
                f"`{_escape_inline(_get(point, 'function', ''))}` |"
            )
        lines.append("")

    dictionary = analysis.get("dictionary", []) or []
    lines.append("### 变异字典\n")
    if dictionary:
        lines.append("```")
        for token in dictionary:
            lines.append(_display(token))
        lines.append("```\n")
    else:
        lines.append("> 无自定义字典。\n")

    seeds = analysis.get("seeds", []) or []
    lines.append("### 种子集\n")
    if seeds:
        for seed in seeds:
            lines.append(f"- `{_escape_inline(seed)}`")
        lines.append("")
    else:
        lines.append("> 无种子文件。\n")

    # ---- 运行统计 ----
    lines.append('## <a id="runstats"></a>运行统计\n')
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    lines.append(f"| 总执行数 | {data['total_execs']} |")
    lines.append(f"| 执行速度 | {data['execs_per_sec']} exec/s |")
    lines.append(f"| 崩溃总数（含重复） | {data['crashes_total']} |")
    lines.append(f"| 超时数 | {data['timeouts']} |")
    lines.append(f"| 语料队列大小 | {data['corpus_size']} |\n")

    return "\n".join(lines)


def _get(obj: Any, key: str, default: Any) -> Any:
    """从 dict 中安全读取字段，缺失时返回默认值（配合 analysis 子结构使用）。"""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default) if hasattr(obj, key) else default
