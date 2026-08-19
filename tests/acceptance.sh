#!/usr/bin/env bash
# acceptance.sh —— 验收指标统计（P7）
#
# 指标与阈值（计划书第一节）：
#   可复现崩溃数 ≥ 3（兜底：自写靶标必出 4 类崩溃）
#   代码覆盖率   ≥ 50% 基本块
#   运行稳定性   ≥ 90%
#
# 用法：
#   tests/acceptance.sh [fuzz 输出目录，默认 ../out]
#   - 有 report.json（P6 产出）时解析真实指标；
#   - 无 report.json（尚未跑 fuzz）时，崩溃数用自写靶标兜底，覆盖/稳定性标 N/A。
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="${1:-$ROOT_DIR/out}"
REPORT="$WORKDIR/report.json"

CRASH_MIN=3
COV_MIN=50
STAB_MIN=90

echo "===== RevFuzz 验收指标统计（P7）====="
echo "fuzz 输出目录: $WORKDIR"
echo

# ---------- 指标 1：可复现崩溃数 ----------
echo "[1] 可复现崩溃数（阈值 ≥ $CRASH_MIN）"
if [ -f "$REPORT" ]; then
    n=$(python3 -c "import json; print(json.load(open('$REPORT')).get('unique_crashes', 0))" 2>/dev/null)
    [ -n "$n" ] && echo "    report.json: unique_crashes = $n" || echo "    report.json 解析失败"
else
    echo "    未发现 report.json（尚未跑 fuzz），改用自写靶标兜底自检："
    if bash "$ROOT_DIR/tests/verify_crashes.sh" >/dev/null 2>&1; then
        echo "    自写靶标 4 类漏洞全部复现 → 可复现崩溃数 = 4"
    else
        echo "    自写靶标自检失败"
    fi
fi

# ---------- 指标 2/3：覆盖率与稳定性（依赖 report.json） ----------
if [ -f "$REPORT" ]; then
    python3 - "$REPORT" "$COV_MIN" "$STAB_MIN" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cov_min, stab_min = int(sys.argv[2]), int(sys.argv[3])

cov = d.get("edges_covered", 0)
tot = d.get("edges_total", 0)
cov_pct = (cov / tot * 100) if tot else None
print(f"\n[2] 代码覆盖率（阈值 ≥ {cov_min}%）")
print(f"    edges_covered/edges_total = {cov}/{tot}")
print(f"    覆盖率 = {cov_pct:.1f}%  {'PASS' if cov_pct is not None and cov_pct >= cov_min else ('N/A（未插桩/未统计）' if cov_pct is None else 'FAIL')}")

execs = d.get("total_execs", 0)
timeouts = d.get("timeouts", 0)
stab = ((execs - timeouts) / execs * 100) if execs else None
print(f"\n[3] 运行稳定性（阈值 ≥ {stab_min}%）")
print(f"    total_execs/timeouts = {execs}/{timeouts}")
print(f"    稳定性 = {stab:.1f}%  {'PASS' if stab is not None and stab >= stab_min else ('N/A（无执行记录）' if stab is None else 'FAIL')}")
PY
else
    echo
    echo "[2] 代码覆盖率（阈值 ≥ $COV_MIN%）  N/A —— 需先跑 fuzz 生成 report.json"
    echo "[3] 运行稳定性（阈值 ≥ $STAB_MIN%）  N/A —— 需先跑 fuzz 生成 report.json"
fi

echo
echo "===== 统计完成 ====="
