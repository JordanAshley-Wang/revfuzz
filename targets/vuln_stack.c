/* vuln_stack.c —— 栈缓冲区溢出（stack-buffer-overflow）
 *
 * 模拟文件格式解析器：输入以魔数 "REVF" 开头时进入解析分支，
 * 后续 body 经 strcpy() 无界拷贝进 32 字节栈缓冲，body 超长即栈溢出。
 *
 * 触发输入（stdin 或文件路径）：
 *   python3 -c "import sys; sys.stdout.buffer.write(b'REVF'+b'A'*64)" | ./vuln_stack
 *   ./vuln_stack <crash_input_file>
 *
 * 参考同类成因：objdump 堆溢出（binutils BFD OOB 写）—— 输入数据触发内存破坏。
 */
#include <stdio.h>
#include <string.h>

#define MAGIC        "REVF"
#define STACK_BUFSZ  32
#define INPUT_CAP    256

static FILE *open_input(int argc, char **argv)
{
    /* 兼容两种喂入方式：argv[1] 文件路径，或 stdin 管道 */
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        if (f)
            return f;
    }
    return stdin;
}

static int parse_body(const char *body)
{
    char buf[STACK_BUFSZ];
    /* 危险点：strcpy 无界拷贝，body 超长时越过 32 字节栈缓冲 → 栈溢出 */
    strcpy(buf, body);
    return (int)strlen(buf);
}

int main(int argc, char **argv)
{
    FILE *in = open_input(argc, argv);
    char input[INPUT_CAP];
    size_t n = fread(input, 1, sizeof(input) - 1, in);
    input[n] = '\0';

    /* 魔数校验：非 REVF 开头直接返回（给 fuzzer 提供分支覆盖） */
    if (n < 4 || memcmp(input, MAGIC, 4) != 0)
        return 0;

    return parse_body(input + 4);
}
