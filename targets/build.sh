#!/usr/bin/env bash
# build.sh —— 编译 4 个漏洞靶标（P7）
#
# 编译器优先级：afl-clang-fast（带插桩，供 afl-showmap 取覆盖率）
#             → clang → gcc（本机无 clang/afl 时回退，仅用于验证崩溃）
#
# Sanitizer：ASan + UBSan，-fno-sanitize-recover=all 使 UBSan 溢出点直接中止
#            （否则 vuln_int 的整数溢出只告警不崩溃）。
# -U_FORTIFY_SOURCE：关闭 glibc 强化检查，避免 strcpy 栈溢出被 __strcpy_chk
#            抢先拦截成 "*** buffer overflow detected ***"（非 ASan 的 stack-buffer-overflow，
#            会导致 P5 分类成 unknown）。
#
# 用法： ./build.sh [输出目录，默认 ./bin]
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-$SRC_DIR/bin}"

# ---- 选择编译器 ----
if command -v afl-clang-fast >/dev/null 2>&1; then
    CC=afl-clang-fast
    INSTRUMENTED=1
elif command -v clang >/dev/null 2>&1; then
    CC=clang
    INSTRUMENTED=0
elif command -v gcc >/dev/null 2>&1; then
    CC=gcc
    INSTRUMENTED=0
else
    echo "错误：未找到 afl-clang-fast / clang / gcc，无法编译" >&2
    exit 1
fi

CFLAGS=(
    -fsanitize=address,undefined
    -fno-sanitize-recover=all
    -O1 -g
    -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
)

mkdir -p "$OUT_DIR"
echo "==> 编译器: $CC (插桩=$INSTRUMENTED)"
echo "==> 输出目录: $OUT_DIR"

TARGETS=(vuln_stack vuln_heap vuln_uaf vuln_int)
for t in "${TARGETS[@]}"; do
    echo "==> 编译 $t ..."
    "$CC" "${CFLAGS[@]}" -o "$OUT_DIR/$t" "$SRC_DIR/$t.c"
done

# ---- 覆盖基准版本 *_ref（纯 afl 插桩，无 sanitizer）----
# sanitizer 会向用户函数注入大量检测分支（如 vuln_stack：目标自身 9 条插桩边，
# ASan 版膨胀到 24 条），使静态边数分母失真、覆盖率恒偏低。
# *_ref 仅供 P2 静态分析统计 edges_total（目标自身逻辑的插桩边数），不用于 fuzz。
if [ "$INSTRUMENTED" = "1" ]; then
    for t in "${TARGETS[@]}"; do
        "$CC" -O1 -g -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
            -o "$OUT_DIR/${t}_ref" "$SRC_DIR/$t.c"
    done
    echo "==> 覆盖基准版本 *_ref 编译完成（仅用于 edges_total 统计）"
fi

echo "==> 完成。二进制位于 $OUT_DIR/"
