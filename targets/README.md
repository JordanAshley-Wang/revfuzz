# RevFuzz 漏洞靶标（P7）

自写的 4 个漏洞靶标，覆盖验收要求的 4 类漏洞，用于端到端测试与验收指标统计。
每个靶标从 stdin 或 `argv[1]` 文件路径读取输入（兼容执行器两种喂入方式）。

| 靶标 | 漏洞类型 | 成因 | 触发输入 |
|------|----------|------|----------|
| `vuln_stack.c` | 栈溢出 `stack-buffer-overflow` | 魔数 `REVF` 校验后 `strcpy` 无界拷入 32 字节栈缓冲 | `REVF` + 64×`A` |
| `vuln_heap.c` | 堆溢出 `heap-buffer-overflow` | 记录长度 N 分配后越界写 `buf[N]`（off-by-one） | `\x04\x00` + 4×`A` |
| `vuln_uaf.c` | 释放后使用 `heap-use-after-free` | `free()` 后未置空，命令流 `f`→`w`/`r` 再次访问 | `fw` 或 `fr` |
| `vuln_int.c` | 整数溢出 `signed integer overflow` | `count * 4` 32 位有符号乘法溢出 | `536870912\n` |

## 快速开始

```bash
# 1) 编译（优先 afl-clang-fast 插桩，无则回退 clang/gcc）
./build.sh                      # 二进制输出到 ./bin/

# 2) 生成初始种子与已知崩溃输入
./gen_corpus.sh                 # 生成 seeds/ 与 triggers/

# 3) 验证「喂输入必崩」（端到端测试，见 ../tests/）
../tests/verify_crashes.sh
```

## 触发验证（手动）

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'REVF'+b'A'*64)" | ./bin/vuln_stack
python3 -c "import sys; sys.stdout.buffer.write(b'\x04\x00'+b'A'*4)" | ./bin/vuln_heap
printf 'fw' | ./bin/vuln_uaf
printf '536870912\n' | ./bin/vuln_int
```

## 编译说明

- `-fsanitize=address,undefined`：ASan 捕获内存类漏洞，UBSan 捕获整数溢出等 UB。
- `-fno-sanitize-recover=all`：**必需**。否则 UBSan 对整数溢出默认只告警不中止，
  `vuln_int` 不会崩溃，无法被 fuzzer 判定为 crash。
- `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`：**必需**（gcc 下）。否则 glibc 强化检查
  会把 `vuln_stack` 的 `strcpy` 替换为 `__strcpy_chk`，报 `*** buffer overflow detected ***`
  而非 ASan 的 `stack-buffer-overflow`，导致 P5 分类为 `unknown`。
- 用 `afl-clang-fast` 编译时目标带插桩，`afl-showmap` 才能取到边覆盖（P3 依赖）。
