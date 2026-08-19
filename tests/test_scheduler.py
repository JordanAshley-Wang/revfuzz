"""P4 单元测试：能量调度 scheduler（D4 里程碑交付）。

运行：python -m unittest tests.test_scheduler -v
     （或 python tests/test_scheduler.py）
"""
from __future__ import annotations

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from contract import Seed
from engine import scheduler as S


def _make_analysis() -> dict:
    """构造一份最小可用的 analysis.json（schema 见 contract.py）。"""
    return {
        "target": "/tmp/vuln",
        "functions": [
            {"name": "main", "addr": 0x401000, "size": 200, "risk_score": 1.0, "calls": []},
            {"name": "parse", "addr": 0x401100, "size": 300, "risk_score": 7.5, "calls": ["strcpy", "fread"]},
            {"name": "echo", "addr": 0x401200, "size": 120, "risk_score": 2.0, "calls": []},
        ],
        "dangerous_calls": [
            {"function": "parse", "api": "strcpy", "addr": 0x401120, "risk": "high"},
        ],
        "input_points": [{"type": "argv", "function": "main"}],
        "dictionary": ["\\x7fELF", "magic"],
        "seeds": ["corpus/seed_0"],
    }


class TestScheduler(unittest.TestCase):

    def setUp(self) -> None:
        random.seed(20260819)

    def test_returns_seed_from_queue(self) -> None:
        queue = [Seed(id=0, path="s0", data=b"a"), Seed(id=1, path="s1", data=b"b")]
        picked = S.pick_seed(queue, {})
        self.assertIn(picked, queue)

    def test_empty_analysis_still_works(self) -> None:
        queue = [Seed(id=0, path="s0", data=b"x")]
        picked = S.pick_seed(queue, {})
        self.assertEqual(picked.id, 0)
        self.assertEqual(picked.risk_score, 1.0)  # 无分析：风险权重 0

    def test_high_risk_seed_preferred(self) -> None:
        """高风险（高覆盖）种子应比低风险种子被选中的次数更多。"""
        analysis = _make_analysis()
        low = Seed(id=0, path="low", data=b"x", found_edges=0)
        high = Seed(id=1, path="high", data=b"y", found_edges=16)
        queue = [low, high]
        counts = {0: 0, 1: 0}
        random.seed(7)
        for _ in range(20000):
            s = S.pick_seed(queue, analysis)
            counts[s.id] += 1
        # 高风险种子贡献边更多 → 覆盖得分更高 → 能量更高 → 被选更多
        self.assertGreater(counts[1], counts[0])

    def test_risk_score_written_back(self) -> None:
        analysis = _make_analysis()
        seed = Seed(id=0, path="s", data=b"x", found_edges=8)
        S.pick_seed([seed], analysis)
        self.assertGreater(seed.risk_score, 1.0)  # 有分析且覆盖深 → 风险分 > 1

    def test_energy_maps_into_range(self) -> None:
        self.assertEqual(S._score_to_energy(1.0, 1.0, 1.0), (1.0 + 32.0) / 2.0)
        e = S._score_to_energy(10.0, 0.0, 10.0)
        self.assertAlmostEqual(e, 32.0)
        e2 = S._score_to_energy(0.0, 0.0, 10.0)
        self.assertAlmostEqual(e2, 1.0)

    def test_high_risk_density_between_0_and_1(self) -> None:
        d = S._high_risk_density(_make_analysis())
        self.assertGreater(d, 0.0)
        self.assertLessEqual(d, 1.0)
        self.assertEqual(S._high_risk_density({}), 0.0)

    def test_empty_queue_raises(self) -> None:
        with self.assertRaises(ValueError):
            S.pick_seed([], {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
