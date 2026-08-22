#!/usr/bin/env python3
"""RevFuzz —— 逆向 Skill 固化的覆盖引导漏洞挖掘工具。

★ 接口文件：CLI 参数与环境变量约定为 D1 定稿，仅 P1 可修改 ★
- CLI 骨架与解析细节：P6 负责完善（--dictionary 解析、参数校验等）
- 集成流程（main 及各 _obtain_* 串联）：P1 负责

环境变量（优先级低于命令行参数）：
  REVFUZZ_TARGET / REVFUZZ_TIMEOUT / REVFUZZ_DICTIONARY / REVFUZZ_CORPUS /
  REVFUZZ_WORKDIR / REVFUZZ_MAX_LEN / REVFUZZ_RUN_TIMEOUT_MS / REVFUZZ_REPORT /
  REVFUZZ_ANALYSIS
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

from contract import load_analysis
from engine.fuzzer import Fuzzer

LOG = logging.getLogger("revfuzz")

_ENV_PREFIX = "REVFUZZ_"


# ================= CLI 骨架（P6） =================

def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(_ENV_PREFIX + name, default)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="revfuzz",
        description="逆向 Skill 固化的覆盖引导 Fuzzer")
    p.add_argument("--target", default=_env("TARGET"),
                   help="目标程序路径 [env REVFUZZ_TARGET]")
    p.add_argument("--timeout", type=int, default=int(_env("TIMEOUT", "3600")),
                   help="运行时长（秒）[env REVFUZZ_TIMEOUT]")
    p.add_argument("--dictionary", default=_env("DICTIONARY"),
                   help="自定义变异字典文件 [env REVFUZZ_DICTIONARY]")
    p.add_argument("--corpus", default=_env("CORPUS"),
                   help="初始种子目录 [env REVFUZZ_CORPUS]")
    p.add_argument("--workdir", default=_env("WORKDIR", "out"),
                   help="输出目录（队列/崩溃/报告/日志）[env REVFUZZ_WORKDIR]")
    p.add_argument("--max-len", type=int, default=int(_env("MAX_LEN", "4096")),
                   help="变异输入最大长度 [env REVFUZZ_MAX_LEN]")
    p.add_argument("--run-timeout-ms", type=int,
                   default=int(_env("RUN_TIMEOUT_MS", "1000")),
                   help="单次执行超时（毫秒）[env REVFUZZ_RUN_TIMEOUT_MS]")
    p.add_argument("--report", choices=["json", "markdown", "both"],
                   default=_env("REPORT", "both"), help="报告格式")
    p.add_argument("--analysis", default=_env("ANALYSIS"),
                   help="复用已有 analysis.json，跳过静态分析 [env REVFUZZ_ANALYSIS]")
    p.add_argument("--no-analysis", action="store_true",
                   help="禁用静态分析，纯 fuzz 模式")
    p.add_argument("-v", "--verbose", action="store_true", help="控制台输出 DEBUG 日志")
    return p.parse_args(argv)


def setup_logging(workdir: str, verbose: bool) -> None:
    """分级日志（P6 完善格式）：DEBUG/INFO/ERROR 写文件，控制台按 -v 调级。"""
    os.makedirs(workdir, exist_ok=True)
    root = logging.getLogger("revfuzz")
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")

    fh = logging.FileHandler(os.path.join(workdir, "revfuzz.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt)
    root.addHandler(ch)


# ================= 集成流程（P1） =================

def _obtain_analysis(args: argparse.Namespace) -> dict | None:
    """静态分析接入点（P2）：优先复用缓存，未就绪则降级为纯 fuzz。"""
    if args.no_analysis:
        return None
    cached = args.analysis or os.path.join(args.workdir, "analysis.json")
    if os.path.isfile(cached):
        LOG.info("复用 analysis.json: %s", cached)
        return load_analysis(cached)
    try:
        from skill.static_analysis import analyze
        LOG.info("静态分析: %s", args.target)
        return analyze(args.target, args.workdir)
    except Exception as e:
        LOG.warning("静态分析失败（%s: %s），以无分析模式运行",
                    type(e).__name__, e)
        return None


def _decode_dict_token(s: str) -> bytes:
    """字典条目 str -> bytes（\\xNN 转义解析，P6 可完善）。"""
    return s.encode("latin-1").decode("unicode_escape").encode("latin-1")


def _obtain_inputs(args: argparse.Namespace,
                   analysis: dict | None) -> tuple[list[str], list[bytes]]:
    """汇总初始种子（corpus 目录 + P2 生成）与变异字典（P2 提取 + 自定义文件）。"""
    corpus: list[str] = []
    if args.corpus and os.path.isdir(args.corpus):
        corpus = [os.path.join(args.corpus, f) for f in sorted(os.listdir(args.corpus))
                  if os.path.isfile(os.path.join(args.corpus, f))]
    if analysis:
        corpus.extend(analysis.get("seeds", []))

    dictionary: list[bytes] = []
    if analysis:
        dictionary.extend(_decode_dict_token(t) for t in analysis.get("dictionary", []))
    if args.dictionary and os.path.isfile(args.dictionary):
        with open(args.dictionary, encoding="utf-8") as f:
            dictionary.extend(_decode_dict_token(line.strip())
                              for line in f if line.strip())
    return corpus, dictionary


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.target:
        print("错误：必须指定 --target（或设 REVFUZZ_TARGET）", file=sys.stderr)
        return 2
    if not os.path.isfile(args.target):
        print(f"错误：目标不存在: {args.target}", file=sys.stderr)
        return 2

    setup_logging(args.workdir, args.verbose)
    LOG.info("RevFuzz start: target=%s workdir=%s", args.target, args.workdir)

    # ① P2 静态分析（可降级）
    analysis = _obtain_analysis(args)
    # ② 种子与字典
    corpus, dictionary = _obtain_inputs(args, analysis)

    # ③ P3 覆盖反馈 + P1 主循环
    from engine.coverage import CoverageRunner
    runner = CoverageRunner(args.target, timeout_ms=args.run_timeout_ms)
    fuzzer = Fuzzer(
        target=args.target,
        corpus=corpus,
        dictionary=dictionary,
        analysis=analysis,
        workdir=args.workdir,
        timeout_s=args.timeout,
        max_len=args.max_len,
        coverage_runner=runner,
    )
    stats = fuzzer.run()

    # ④ P6 报告
    from report.reporter import generate_report
    fmts = ["json", "markdown"] if args.report == "both" else [args.report]
    for fmt in fmts:
        try:
            generate_report(stats, fuzzer.crashes, analysis, fmt,
                            out_dir=args.workdir)
        except NotImplementedError:
            LOG.warning("报告模块未就绪（P6），跳过 %s 报告", fmt)

    LOG.info("RevFuzz done: unique_crashes=%d edges=%d/%d",
             stats.unique_crashes, stats.edges_covered, stats.edges_total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
