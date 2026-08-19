"""P4 单元测试：变异器 mutator（D4 里程碑交付）。

运行：python -m unittest tests.test_mutator -v
     （或 python tests/test_mutator.py）
"""
from __future__ import annotations

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import mutator as M


class TestMutator(unittest.TestCase):
    """四种变异策略的正确性与边界。"""

    def setUp(self) -> None:
        random.seed(20260819)

    def test_empty_seed_falls_back(self) -> None:
        out = M.mutate(b"", [], max_len=64)
        self.assertGreaterEqual(len(out), 1)
        self.assertLessEqual(len(out), 64)

    def test_max_len_respected_with_dict_growth(self) -> None:
        # 字典 token 很长，插入会超长，需被截断到 max_len
        dictionary = [b"A" * 128, b"B" * 256]
        for _ in range(2000):
            out = M.mutate(b"\x00" * 8, dictionary, max_len=64)
            self.assertLessEqual(len(out), 64)

    def test_bitflip_keeps_length(self) -> None:
        buf = bytearray(b"hello world")
        before = bytes(buf)
        M._bitflip(buf)
        self.assertEqual(len(buf), len(before))
        # 翻转 1~8 bit，至少改变 1 个字节（除非同一 bit 被重复翻转恰好抵消，概率极低）
        self.assertNotEqual(bytes(buf), before)

    def test_arith_wraps_and_keeps_length(self) -> None:
        buf = bytearray(b"\xff\xff\xff\xff")
        M._arith(buf)
        self.assertEqual(len(buf), 4)
        # 0xffffffff + 正增量必须回绕（结果 < 0xffffffff）
        self.assertLess(int.from_bytes(buf, "little"), 0xFFFFFFFF)

    def test_dict_insert_and_overwrite(self) -> None:
        tok = b"magic"
        buf = bytearray(b"0123456789")
        M._dict_insert(buf, tok)
        self.assertIn(tok, bytes(buf))
        buf2 = bytearray(b"0123456789")
        M._dict_overwrite(buf2, tok)
        self.assertIn(tok, bytes(buf2))

    def test_havoc_produces_valid_bytes(self) -> None:
        for _ in range(500):
            buf = bytearray(b"\x00" * 32)
            M._havoc(buf, [b"TOK"])
            self.assertIsInstance(bytes(buf), bytes)

    def test_deterministic_under_fixed_seed(self) -> None:
        random.seed(42)
        a = M.mutate(b"seed-data", [b"k1", b"k2"], 128)
        random.seed(42)
        b = M.mutate(b"seed-data", [b"k1", b"k2"], 128)
        self.assertEqual(a, b)

    def test_no_dictionary_still_mutates(self) -> None:
        for _ in range(200):
            out = M.mutate(b"abc", [], 64)
            self.assertGreaterEqual(len(out), 1)
            self.assertLessEqual(len(out), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
