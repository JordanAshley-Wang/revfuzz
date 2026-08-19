"""报告生成 —— P6 负责（D3~D4 / D9 美化）。

输出 JSON 与 Markdown 两种格式，内容包含（功能要求 #4）：
崩溃详情、覆盖率统计、逆向分析结果、漏洞分类标签、复现命令。

接口契约见 contract.py（CampaignStats / CrashInfo），签名不可改。
"""
from __future__ import annotations

from contract import CampaignStats, CrashInfo


def generate_report(campaign_stats: CampaignStats, crashes: list[CrashInfo],
                    analysis: dict | None, fmt: str, out_dir: str = "out") -> None:
    """生成测试报告。

    - fmt ∈ {"json", "markdown"}：分别输出 out_dir/report.json / report.md；
    - analysis 可能为 None（无静态分析模式），报告需降级展示。
    """
    raise NotImplementedError("P6 D3~D4 实现：JSON/Markdown 报告")
