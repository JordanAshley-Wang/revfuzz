# RevFuzz —— 逆向 Skill 固化的覆盖引导漏洞挖掘工具

基于"人工挖漏洞流程固化"思路设计的自动化漏洞挖掘工具：把逆向分析（函数定位、敏感
API 识别、输入点分析）固化为自动化 Skill，产出高风险画像与智能种子，驱动覆盖引导
Fuzzer，再由 Sanitizer 动态检测 + 自动分类 + 崩溃最小化完成闭环。

设计参考了 [VPGFUZZ（IEEE TIFS 2025）](https://mp.weixin.qq.com/s/GjALPZLvlXQYgvBXG2K75A)
的"漏洞路径/风险引导"思想（以静态风险画像加权种子调度），以及真实漏洞案例的成因模式
（[objdump 堆溢出](https://mp.weixin.qq.com/s/G8DyQVwpo1LiU_IP7KZUig)、
[Copy Fail CVE-2026-31431](https://mp.weixin.qq.com/s/Pwm7sJ12K20FKbzxzFELkw)）。

## 功能特性

- **逆向 Skill 固化**：ELF 符号表函数定位 + objdump 反汇编归因（危险 API 调用定位到
  具体调用函数，自动剥离 ASan `__interceptor_` 前缀、剔除 sanitizer/afl 运行时噪声），
  按 API 危险度分级加权生成函数 `risk_score`；识别输入点（stdin/argv/文件）；
  从 `.rodata` 提取字典；生成边界值/格式化串/路径注入等智能种子。
- **覆盖引导 Fuzzing**：集成 `afl-showmap` 收集边覆盖（单次运行同时取边覆盖、执行
  状态与 stderr）；变异策略含位翻转、算术变异、字典替换、Havoc；种子调度按
  `score = 覆盖得分 × (1 + 风险权重)` 加权轮盘赌（VPGFUZZ 式 exploit 优先）。
- **漏洞检测与分类**：ASan/UBSan 动态检测，自动分类堆溢出、栈溢出、UAF、整数溢出；
  按 `类型+符号化位置` 去重；内置 ddmin 崩溃最小化；ASan 未符号化时用 addr2line 兜底
  定位到 `文件:行`。
- **报告与日志**：JSON + Markdown 双格式报告（崩溃详情、覆盖率、逆向分析结果、漏洞
  标签、复现命令、最小化输入）；DEBUG/INFO/ERROR 分级日志写入 `revfuzz.log`。
- **交互扩展**：`--target` / `--timeout` / `--dictionary` / `--corpus` 等参数齐全，
  全部支持 `REVFUZZ_*` 环境变量配置。

## 系统架构

```
┌───────────────────────── skill/（P2 逆向 Skill） ─────────────────────────┐
│ static_analysis.py  函数定位/敏感API归因/输入点/字典提取/静态边统计          │
│ seed_gen.py         智能种子（strcpy边界/格式化串/整数边界/路径注入）          │
└──────────────────────┬───────────────────────────────────────────────────┘
                       ▼ analysis.json（contract.py 定义 schema）
┌───────────────────────── engine/（P1/P3/P4/P5） ──────────────────────────┐
│ fuzzer.py     主循环：选种→变异→执行→入队/崩溃处理                          │
│ coverage.py   afl-showmap 边覆盖 + 状态判定（单跑拿齐，超时按进程组清理）      │
│ executor.py   argv/file/stdin 三种喂入 + 超时控制                           │
│ mutator.py    bitflip/arith/dict/havoc 变异策略                            │
│ scheduler.py  风险加权能量调度（轮盘赌，能量 [1,32]）                        │
│ triage.py     ASan/UBSan 分类 + 去重 + ddmin 最小化 + addr2line 符号化      │
└──────────────────────┬───────────────────────────────────────────────────┘
                       ▼
┌───────────────────────── report/（P6 输出） ──────────────────────────────┐
│ reporter.py   report.json + report.md；logger.py 分级日志                  │
└──────────────────────────────────────────────────────────────────────────┘
```

## 环境依赖

- Python ≥ 3.10，`pyelftools`
- afl++（`afl-clang-fast` 编译插桩、`afl-showmap` 取覆盖；缺失时退化为盲 fuzz 并告警）
- binutils（`objdump` 静态分析、`addr2line` 崩溃符号化）
- clang/gcc（无 afl-clang-fast 时的回退编译器）

```bash
sudo apt install afl++ binutils clang
pip install pyelftools
```

## 快速开始

```bash
# 1) 编译 4 个漏洞靶标（ASan+UBSan 插桩版 + 无 sanitizer 的 *_ref 覆盖基准版）
bash targets/build.sh

# 2) 生成初始种子语料
bash targets/gen_corpus.sh

# 3) 跑一轮 fuzz（静态分析 → 智能种子 → 覆盖引导 fuzz → 报告）
python3 main.py --target targets/bin/vuln_stack --corpus targets/seeds --timeout 120

# 4) 验收指标统计（崩溃数 / 覆盖率 / 稳定性）
bash tests/acceptance.sh out
```

输出目录（默认 `out/`，可用 `--workdir` 改）：

```
out/
├── analysis.json   # 逆向分析结果（函数/危险调用/输入点/字典/edges_total）
├── report.json     # 结构化报告（验收指标数据源）
├── report.md       # 人类可读报告
├── crashes/        # 崩溃样本（*.min 为 ddmin 最小化输入）
├── queue/          # fuzz 过程中发现的新种子
├── seeds/  dict.txt
└── revfuzz.log     # DEBUG/INFO/ERROR 分级日志
```

## 命令行参数

| 参数 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `--target` | `REVFUZZ_TARGET` | 必填 | 目标程序路径 |
| `--timeout` | `REVFUZZ_TIMEOUT` | 3600 | 运行时长（秒） |
| `--dictionary` | `REVFUZZ_DICTIONARY` | - | 自定义变异字典文件 |
| `--corpus` | `REVFUZZ_CORPUS` | - | 初始种子目录 |
| `--workdir` | `REVFUZZ_WORKDIR` | `out` | 输出目录 |
| `--max-len` | `REVFUZZ_MAX_LEN` | 4096 | 变异输入最大长度 |
| `--run-timeout-ms` | `REVFUZZ_RUN_TIMEOUT_MS` | 1000 | 单次执行超时（毫秒） |
| `--report` | `REVFUZZ_REPORT` | `both` | 报告格式 json/markdown/both |
| `--analysis` | `REVFUZZ_ANALYSIS` | - | 复用已有 analysis.json |
| `--no-analysis` | - | - | 禁用静态分析，纯 fuzz 模式 |
| `-v/--verbose` | - | - | 控制台输出 DEBUG 日志 |

## 实测验收结果（4 个靶标，各 120s）

| 靶标 | 去重崩溃 | 漏洞类型与位置 | 覆盖率 | 稳定性 |
| --- | --- | --- | --- | --- |
| vuln_stack | 2 | stack-buffer-overflow `vuln_stack.c:34` + strcpy-param-overlap | 88.9% | 100% |
| vuln_heap | 1 | heap-buffer-overflow `vuln_heap.c:46` | 70.0% | 100% |
| vuln_int | 1 | integer-overflow `vuln_int.c:42` | 100% | 99.5% |
| vuln_uaf | 2 | heap-use-after-free `vuln_uaf.c:47` / `:50` | 83.3% | 100% |

合计 **6 个可复现漏洞触发点**（阈值 3），覆盖率 70%~100%（阈值 50%），
稳定性 ≥ 99.5%（阈值 90%）。

> 覆盖率口径：`edges_total` 取目标自身逻辑的 afl 插桩边数（`__sancov_guards` 段
> 精确计数，优先用无 sanitizer 的 `*_ref` 基准版，避免 ASan 注入分支虚高分母）。

## 测试

```bash
# 单元测试 + 端到端集成测试（25 个用例）
python3 -m unittest discover -s tests -p 'test_*.py'

# 靶标必崩自检（不依赖 fuzz）
bash tests/verify_crashes.sh

# 验收指标统计
bash tests/acceptance.sh <workdir>
```

## 已知限制与注意事项

- 本工具面向**用户态程序**；文中参考的内核漏洞（Copy Fail）仅作为静态分析演示对象，
  不在 fuzz 目标范围内。
- ASan 崩溃时默认 fork `llvm-symbolizer` 做符号化；若环境中 symbolizer 版本与 ASan
  运行时不兼容会严重拖慢甚至死循环，工具已通过 `ASAN_OPTIONS=symbolize=0` 关闭外部
  符号化并改用 addr2line 兜底。
- 仅用于授权范围内的安全研究与教学，靶标为自写漏洞程序，请勿用于未授权目标。
