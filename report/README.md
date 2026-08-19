# RevFuzz report 模块（P6）

报告与交互开发模块：负责 **双格式报告生成**（JSON / Markdown），
严格按 `contract.py`（D1 定稿）的数据结构交付。

## 目录

- [模块组成](#模块组成)
- [接口契约](#接口契约)
- [使用方法](#使用方法)
- [输出格式](#输出格式)
- [测试](#测试)

## 模块组成

| 文件 | 职责 |
| --- | --- |
| `report/reporter.py` | 报告生成：`generate_report(...)` |
| `report/logger.py` | 分级日志助手：`get_logger` / 幂等 `init_logger` |
| `tests/mock_data.py` | 三组场景 mock 数据（正常/无崩溃/多崩溃） |
| `tests/test_reporter.py` | 报告模块自动化测试 |

## 接口契约

```python
from contract import CampaignStats, CrashInfo

def generate_report(
    campaign_stats: CampaignStats,
    crashes: list[CrashInfo],
    analysis: dict | None,        # None = 无静态分析模式，报告降级展示
    fmt: str,                     # 仅支持 "json" / "markdown"
    out_dir: str = "out",
) -> None
```

- **CampaignStats**（P1 构造）：`target` / `start_time` / `elapsed_s` / `total_execs` /
  `execs_per_sec` / `edges_covered` / `edges_total` / `crashes` / `unique_crashes` /
  `timeouts` / `corpus_size`
- **CrashInfo**（P5 产出）：`vuln_type` / `location` / `dedup_key` / `input_path` /
  `minimized_input` / `repro_cmd` / `raw_stderr`
- **analysis**（P2 产出）：schema 见 `contract.ANALYSIS_REQUIRED_KEYS`

> 兼容性：`analysis=None` 或缺字段时报告用默认值兜底，绝不崩溃。

## 使用方法

### 团队集成（由 P1 的 main.py 调用）

P1 的 `main.py` 已通过 `generate_report(stats, fuzzer.crashes, analysis, fmt, out_dir=args.workdir)`
自动生成报告，P6 无需改动 main.py。

### 独立验证

```python
from contract import CampaignStats, CrashInfo
from report.reporter import generate_report
from tests.mock_data import mock_normal

stats, crashes, analysis = mock_normal()
generate_report(stats, crashes, analysis, "json", "out")
generate_report(stats, crashes, analysis, "markdown", "out")
```

## 输出格式

### JSON（report.json）

顶层包含验收指标字段（与 `tests/acceptance.sh` 解析口径一致）：

| 字段 | 含义 |
| --- | --- |
| `unique_crashes` | 可复现崩溃数（验收指标） |
| `edges_covered` / `edges_total` | 已命中边 / 总边数（覆盖率） |
| `total_execs` / `timeouts` | 总执行 / 超时数（稳定性） |

另含可读性指标 `code_coverage` / `runtime_stability`，以及
`basic_info` / `crash_details` / `reverse_analysis` 等模块。

### Markdown（report.md）

- 顶部大标题 + 生成时间
- 目录导航（锚点可跳转）
- **验收指标高亮表格**放在最前
- 崩溃列表表格 + 每个崩溃的详情块（含 ASan/UBSan 原始输出）
- 覆盖率 / 运行统计表格
- 逆向分析分章节，敏感 API、输入点重点标注

## 测试

```bash
python -m unittest tests.test_reporter -v
```

覆盖：三组场景（正常 / 无崩溃 / 多崩溃）、`analysis=None` 降级、
缺字段兜底、非法 fmt、1000+ 崩溃性能（< 2 秒）。
