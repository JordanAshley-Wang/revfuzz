#!/usr/bin/env bash
# gen_corpus.sh —— 生成初始种子（seeds/）与已知崩溃触发输入（triggers/）（P7）
#
# seeds/   不崩溃、用于引导 fuzzer 覆盖的起始输入
# triggers/ 手动验证「喂输入必崩」的已知崩溃输入（tests/verify_crashes.sh 使用）
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEED_DIR="$SRC_DIR/seeds"
TRIG_DIR="$SRC_DIR/triggers"

mkdir -p "$SEED_DIR" "$TRIG_DIR"

python3 - "$SEED_DIR" "$TRIG_DIR" <<'PY'
import os, sys
seed_dir, trig_dir = sys.argv[1], sys.argv[2]

# 每个靶标 1~2 个安全种子（走解析路径但不触发漏洞）
seeds = {
    "stack_seed": b"REVF" + b"A" * 16,        # 合法魔数，长度 16 < 32，不崩
    "heap_seed":  b"\x04\x00" + b"A" * 2,     # n=4 但只给 2 字节数据，走解析不崩
    "uaf_f":      b"f",                        # 只释放，不二次访问，不崩
    "uaf_w":      b"w",                        # 只写，不释放，不崩
    "int_seed":   b"100\n",                    # count=100，无溢出
}

# 已知必崩输入：与 4 类漏洞一一对应
triggers = {
    "stack_crash": b"REVF" + b"A" * 64,        # 栈溢出
    "heap_crash":  b"\x04\x00" + b"A" * 4,     # 堆溢出（读满 n 后越界写 buf[n]）
    "uaf_crash":   b"fw",                       # 释放后写 → UAF
    "int_crash":   b"536870912\n",             # 2^29 × 4 溢出 INT_MAX
}

for name, data in seeds.items():
    with open(os.path.join(seed_dir, name), "wb") as f:
        f.write(data)
for name, data in triggers.items():
    with open(os.path.join(trig_dir, name), "wb") as f:
        f.write(data)

print("seeds   :", ", ".join(sorted(os.listdir(seed_dir))))
print("triggers:", ", ".join(sorted(os.listdir(trig_dir))))
PY
