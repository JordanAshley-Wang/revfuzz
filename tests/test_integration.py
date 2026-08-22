#!/usr/bin/env python3
"""端到端集成测试：静态分析 → 覆盖引导 fuzz → 崩溃分类（P1/P2/P3/P5 串联）。

依赖已编译靶标（bash targets/build.sh）与 afl-showmap；缺失时自动跳过。
运行：python3 -m unittest tests.test_integration -v
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from contract import ANALYSIS_REQUIRED_KEYS  # noqa: E402
from engine.coverage import CoverageRunner  # noqa: E402
from engine.fuzzer import Fuzzer  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
TARGET = os.path.join(ROOT, "targets", "bin", "vuln_stack")
SEEDS_DIR = os.path.join(ROOT, "targets", "seeds")

# 魔数 "REVF" + 超长 body：必触发 vuln_stack 的 strcpy 栈溢出
STACK_TRIGGER = b"REVF" + b"A" * 64


@unittest.skipUnless(os.path.isfile(TARGET), "靶标未编译（先跑 targets/build.sh）")
@unittest.skipUnless(shutil.which("afl-showmap"), "缺少 afl-showmap")
class TestIntegration(unittest.TestCase):
    def test_coverage_runner_single_run(self) -> None:
        """P3：单次运行同时拿到边覆盖与状态；崩溃输入可被识别且 stderr 含 ASan 报告。"""
        runner = CoverageRunner(TARGET, timeout_ms=2000)
        ok = runner.run(b"REVF" + b"A" * 8)
        self.assertEqual(ok.status, "ok")
        self.assertGreater(len(ok.edges), 0)

        crash = runner.run(STACK_TRIGGER)
        self.assertEqual(crash.status, "crash")
        self.assertIn(b"AddressSanitizer", crash.stderr)

    def test_static_analysis_schema(self) -> None:
        """P2：analyze() 产出契约必需键，且 edges_total 取目标自身逻辑边数（9）。"""
        from skill.static_analysis import analyze

        with tempfile.TemporaryDirectory() as workdir:
            analysis = analyze(TARGET, workdir)
            for key in ANALYSIS_REQUIRED_KEYS:
                self.assertIn(key, analysis, f"analysis 缺键 {key}")
            # vuln_stack_ref（无 sanitizer 基准版）的 sancov guard 数
            self.assertEqual(analysis["edges_total"], 9)
            self.assertGreater(len(analysis["seeds"]), 0, "智能种子未接线")
            self.assertTrue(os.path.isfile(os.path.join(workdir, "analysis.json")))
            # 风险归因：strcpy 调用应归因到 parse_body 且带权重
            risky = [f for f in analysis["functions"] if f["risk_score"] > 0]
            self.assertTrue(risky, "risk_score 全为 0，风险加权调度会退化")

    def test_fuzzer_finds_stack_overflow(self) -> None:
        """P1+P4+P5：确定性（固定 rng）fuzz 能找到并正确分类栈溢出崩溃。

        语料用贴近溢出边界的种子（REVF + 30×'A'，再长 3 字节即崩），
        字典含长 token，保证在有限 execs 内确定性触发，不依赖纯运气。
        """
        corpus = [b"REVF" + b"A" * 20, b"REVF" + b"A" * 30, b"\x00"]
        with tempfile.TemporaryDirectory() as workdir:
            for i, data in enumerate(corpus):
                with open(os.path.join(workdir, f"seed_{i}"), "wb") as f:
                    f.write(data)
            fuzzer = Fuzzer(
                target=TARGET,
                corpus=[os.path.join(workdir, f"seed_{i}") for i in range(3)],
                dictionary=[b"REVF", b"A" * 16],
                analysis={},
                workdir=workdir,
                timeout_s=300,
                max_execs=800,
                seed_rng=1234,
            )
            stats = fuzzer.run()
            self.assertGreaterEqual(stats.unique_crashes, 1, "800 次执行内未发现崩溃")
            types = {c.vuln_type for c in fuzzer.crashes}
            self.assertIn("stack-buffer-overflow", types)
            top = fuzzer.crashes[0]
            self.assertTrue(os.path.isfile(top.input_path))
            self.assertIn(TARGET, top.repro_cmd, "repro_cmd 未替换 <target> 占位符")
            self.assertIsNotNone(top.minimized_input, "崩溃最小化未接线")


if __name__ == "__main__":
    unittest.main()
