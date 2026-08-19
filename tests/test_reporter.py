"""P6 报告模块测试。

运行：python -m unittest tests.test_reporter -v
     （或 python tests/test_reporter.py）
覆盖：三组场景（正常/无崩溃/多崩溃）、analysis=None 降级、
缺字段兜底、非法 fmt、1000+ 崩溃性能（< 2 秒）。
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report.reporter import generate_report  # noqa: E402
from tests.mock_data import mock_many_crash, mock_no_crash, mock_normal  # noqa: E402


class TestJsonReport(unittest.TestCase):
    def test_normal_scenario(self) -> None:
        stats, crashes, analysis = mock_normal()
        with tempfile.TemporaryDirectory() as tmp:
            generate_report(stats, crashes, analysis, "json", tmp)
            data = json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))

        # 顶层验收字段（acceptance.sh 解析口径）
        for key in ("unique_crashes", "edges_covered", "edges_total", "total_execs", "timeouts"):
            self.assertIn(key, data, f"缺少顶层字段 {key}")
        self.assertEqual(data["unique_crashes"], 3)
        self.assertEqual(data["edges_covered"], 538)
        self.assertEqual(data["edges_total"], 1200)
        # 覆盖率口径：edges_covered / edges_total * 100（保留 2 位）
        self.assertAlmostEqual(data["code_coverage"], 44.83, places=2)
        # 崩溃列表完整 CrashInfo 字段
        first = data["crash_details"][0]
        for key in ("vuln_type", "location", "dedup_key", "input_path", "minimized_input", "repro_cmd", "raw_stderr"):
            self.assertIn(key, first)
        # 逆向分析完整字段
        for key in ("target", "functions", "dangerous_calls", "input_points", "dictionary", "seeds"):
            self.assertIn(key, data["reverse_analysis"])

    def test_no_crash_scenario(self) -> None:
        stats, crashes, analysis = mock_no_crash()
        with tempfile.TemporaryDirectory() as tmp:
            generate_report(stats, crashes, analysis, "json", tmp)
            data = json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(data["unique_crashes"], 0)
        self.assertEqual(data["code_coverage"], 0.0)
        self.assertEqual(data["crash_details"], [])

    def test_many_crash_scenario(self) -> None:
        stats, crashes, analysis = mock_many_crash(30)
        with tempfile.TemporaryDirectory() as tmp:
            generate_report(stats, crashes, analysis, "json", tmp)
            data = json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(data["unique_crashes"], 30)
        self.assertEqual(len(data["crash_details"]), 30)

    def test_analysis_none_degrades(self) -> None:
        """无分析模式：analysis=None 时报告正常生成，逆向分析降级为默认值。"""
        stats, crashes, _ = mock_normal()
        with tempfile.TemporaryDirectory() as tmp:
            generate_report(stats, crashes, None, "json", tmp)
            data = json.loads((Path(tmp) / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(data["reverse_analysis"]["functions"], [])
        self.assertEqual(data["reverse_analysis"]["dangerous_calls"], [])

    def test_invalid_fmt_raises(self) -> None:
        stats, crashes, analysis = mock_no_crash()
        with self.assertRaises(ValueError):
            generate_report(stats, crashes, analysis, "xml", tempfile.mkdtemp())


class TestMarkdownReport(unittest.TestCase):
    def test_markdown_structure(self) -> None:
        stats, crashes, analysis = mock_normal()
        with tempfile.TemporaryDirectory() as tmp:
            generate_report(stats, crashes, analysis, "markdown", tmp)
            md = (Path(tmp) / "report.md").read_text(encoding="utf-8")
        self.assertIn("RevFuzz 模糊测试报告", md)
        self.assertIn("生成时间", md)
        self.assertIn("## 目录", md)
        # 验收指标表格在基本信息之前（第一观感）
        self.assertLess(md.find("验收指标"), md.find("基本信息"))
        # 崩溃详情块
        self.assertIn("### 崩溃详情 #1", md)
        self.assertIn("危险调用（敏感 API）", md)
        self.assertIn("输入点", md)
        # 无崩溃时给出提示
        stats0, _, _ = mock_no_crash()
        with tempfile.TemporaryDirectory() as tmp0:
            generate_report(stats0, [], None, "markdown", tmp0)
            md0 = (Path(tmp0) / "report.md").read_text(encoding="utf-8")
        self.assertIn("未产生可复现崩溃", md0)


class TestPerformance(unittest.TestCase):
    def test_many_crashes_under_2s(self) -> None:
        """1000+ 崩溃下双格式报告生成时间不超过 2 秒。"""
        stats, crashes, analysis = mock_many_crash(1000)
        start = time.perf_counter()
        with tempfile.TemporaryDirectory() as tmp:
            generate_report(stats, crashes, analysis, "json", tmp)
            generate_report(stats, crashes, analysis, "markdown", tmp)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 2.0, f"1000 崩溃双报告耗时 {elapsed:.2f}s，超过 2s 预算")


if __name__ == "__main__":
    unittest.main(verbosity=2)
