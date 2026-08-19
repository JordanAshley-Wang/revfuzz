#!/usr/bin/env bash
# verify_crashes.sh —— 端到端测试：验证 4 个漏洞靶标「喂输入必崩」且报出正确漏洞类型（P7）
#
# 依赖：targets/build.sh（编译）、targets/gen_corpus.sh（生成触发输入）
# 用法： tests/verify_crashes.sh
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGETS_DIR="$ROOT_DIR/targets"
BIN_DIR="$TARGETS_DIR/bin"
TRIG_DIR="$TARGETS_DIR/triggers"

# 靶标 -> 期望的 ASan/UBSan 特征串
declare -A EXPECT=(
    [vuln_stack]="stack-buffer-overflow"
    [vuln_heap]="heap-buffer-overflow"
    [vuln_uaf]="heap-use-after-free"
    [vuln_int]="signed integer overflow"
)
# 靶标 -> 触发输入文件名（gen_corpus.sh 生成，二进制安全经文件喂入）
declare -A TRIG=(
    [vuln_stack]="stack_crash"
    [vuln_heap]="heap_crash"
    [vuln_uaf]="uaf_crash"
    [vuln_int]="int_crash"
)

echo "==> 构建靶标 ..."
bash "$TARGETS_DIR/build.sh" "$BIN_DIR" || { echo "构建失败"; exit 1; }

echo "==> 生成触发输入 ..."
bash "$TARGETS_DIR/gen_corpus.sh" || { echo "生成触发输入失败"; exit 1; }

echo
echo "==> 验证「喂输入必崩」"
fail=0
pass=0
for t in vuln_stack vuln_heap vuln_uaf vuln_int; do
    bin="$BIN_DIR/$t"
    trig="$TRIG_DIR/${TRIG[$t]}"
    exp="${EXPECT[$t]}"

    if [ ! -x "$bin" ]; then
        printf "  [MISSING] %-12s 二进制不存在: %s\n" "$t" "$bin"
        fail=1
        continue
    fi

    out=$("$bin" < "$trig" 2>&1)
    ec=$?
    if [ "$ec" -ne 0 ] && echo "$out" | grep -q "$exp"; then
        printf "  [PASS] %-12s exit=%-3d 检出 %s\n" "$t" "$ec" "$exp"
        pass=$((pass + 1))
    else
        printf "  [FAIL] %-12s exit=%-3d 期望「%s」未检出\n" "$t" "$ec" "$exp"
        echo "$out" | head -3 | sed 's/^/         /'
        fail=1
    fi
done

echo
echo "结果：$pass/4 靶标按预期崩溃"
if [ "$fail" -eq 0 ]; then
    echo "4 类漏洞全部复现（stack/heap/uaf/int），满足验收「可复现崩溃数 ≥ 3」兜底策略"
    exit 0
else
    echo "存在失败项，请检查编译或触发输入"
    exit 1
fi
