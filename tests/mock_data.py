"""P6 测试用 mock 数据：正常 / 无崩溃 / 多崩溃 三组场景。

每组返回 (CampaignStats, list[CrashInfo], analysis) 三元组，
字段严格对齐 contract.py 定义的数据结构。
"""

from __future__ import annotations

import time

from contract import CampaignStats, CrashInfo


def mock_normal() -> tuple[CampaignStats, list[CrashInfo], dict | None]:
    """正常场景：少量可复现崩溃，覆盖率/稳定性适中。"""
    stats = CampaignStats(
        target="/path/to/vuln_binary",
        start_time=time.time() - 60,
        elapsed_s=60.0,
        total_execs=30000,
        execs_per_sec=500.0,
        edges_covered=538,
        edges_total=1200,
        crashes=5,
        unique_crashes=3,
        timeouts=120,
        corpus_size=128,
    )
    crashes = [
        CrashInfo(
            vuln_type="stack-buffer-overflow",
            location="parse_header:0x4010b8",
            dedup_key="stack-overflow@parse_header@0x4010b8",
            input_path="out/crashes/id_000000.bin",
            minimized_input="out/minimized/id_000000.bin",
            repro_cmd="./targets/vuln_stack out/crashes/id_000000.bin",
            raw_stderr=b"ERROR: AddressSanitizer: stack-buffer-overflow on address ...",
        ),
        CrashInfo(
            vuln_type="heap-use-after-free",
            location="free_links:0x40123a",
            dedup_key="uaf@free_links@0x40123a",
            input_path="out/crashes/id_000001.bin",
            minimized_input=None,  # 未最小化
            repro_cmd="./targets/vuln_uaf out/crashes/id_000001.bin",
            raw_stderr=b"ERROR: AddressSanitizer: heap-use-after-free on address ...",
        ),
        CrashInfo(
            vuln_type="integer-overflow",
            location="calc_size:0x401a10",
            dedup_key="int-overflow@calc_size@0x401a10",
            input_path="out/crashes/id_000002.bin",
            minimized_input="out/minimized/id_000002.bin",
            repro_cmd="./targets/vuln_int out/crashes/id_000002.bin",
            raw_stderr=b"",
        ),
    ]
    analysis: dict = {
        "target": "/path/to/vuln_binary",
        "functions": [
            {"name": "parse_header", "addr": 0x401090, "size": 256, "risk_score": 8.5, "calls": ["strcpy", "memcpy"]},
            {"name": "main", "addr": 0x401B00, "size": 120, "risk_score": 4.0, "calls": ["fread"]},
        ],
        "dangerous_calls": [
            {"function": "parse_header", "api": "strcpy", "addr": 0x4010B8, "risk": "high"},
            {"function": "parse_header", "api": "memcpy", "addr": 0x4010D0, "risk": "medium"},
        ],
        "input_points": [
            {"type": "argv", "function": "main"},
            {"type": "file", "function": "parse_header"},
        ],
        "dictionary": ["\\x7fELF", "\\x02\\x01\\x01", "magic_str"],
        "seeds": ["corpus/seed_0", "corpus/seed_1", "corpus/seed_2"],
    }
    return stats, crashes, analysis


def mock_no_crash() -> tuple[CampaignStats, list[CrashInfo], dict | None]:
    """无崩溃场景：崩溃列表为空，覆盖率为 0。"""
    stats = CampaignStats(
        target="/path/to/vuln_binary",
        start_time=time.time() - 60,
        elapsed_s=60.0,
        total_execs=30000,
        execs_per_sec=500.0,
        edges_covered=0,
        edges_total=1200,
        crashes=0,
        unique_crashes=0,
        timeouts=240,
        corpus_size=64,
    )
    analysis: dict = {
        "target": "/path/to/vuln_binary",
        "functions": [],
        "dangerous_calls": [],
        "input_points": [],
        "dictionary": [],
        "seeds": [],
    }
    return stats, [], analysis


def mock_many_crash(count: int = 30) -> tuple[CampaignStats, list[CrashInfo], dict | None]:
    """多崩溃场景：构造 count 个崩溃，覆盖多种漏洞类型。"""
    stats = CampaignStats(
        target="/path/to/vuln_binary",
        start_time=time.time() - 120,
        elapsed_s=120.0,
        total_execs=60000,
        execs_per_sec=500.0,
        edges_covered=900,
        edges_total=1500,
        crashes=count,
        unique_crashes=count,
        timeouts=600,
        corpus_size=256,
    )
    vuln_pool = [
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "heap-use-after-free",
        "integer-overflow",
        "unknown",
    ]
    crashes = [
        CrashInfo(
            vuln_type=vuln_pool[i % len(vuln_pool)],
            location=f"func_{i}:0x{0x400000 + i * 0x100:x}",
            dedup_key=f"crash-{i}@func_{i}",
            input_path=f"out/crashes/id_{i:06d}.bin",
            minimized_input=f"out/minimized/id_{i:06d}.bin",
            repro_cmd=f"./targets/vuln out/crashes/id_{i:06d}.bin",
            raw_stderr=b"",
        )
        for i in range(count)
    ]
    analysis: dict = {
        "target": "/path/to/vuln_binary",
        "functions": [{"name": "func_0", "addr": 0x400000, "size": 128, "risk_score": 7.0, "calls": ["strcpy"]}],
        "dangerous_calls": [{"function": "func_0", "api": "strcpy", "addr": 0x400100, "risk": "high"}],
        "input_points": [{"type": "argv", "function": "main"}],
        "dictionary": ["\\x7fELF"],
        "seeds": ["corpus/seed_0"],
    }
    return stats, crashes, analysis
