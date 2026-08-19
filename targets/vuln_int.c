/* vuln_int.c —— 有符号整数溢出（integer-overflow）
 *
 * 模拟长度计算：从输入解析 count，计算 total = count * 4。
 * 漏洞：count 很大时 32 位有符号乘法溢出（UB），UBSan 捕获
 *       "runtime error: signed integer overflow"。
 *
 * 触发输入（stdin 或文件路径）：
 *   printf '536870912\n' | ./vuln_int   # 2^29，×4 后溢出 INT_MAX
 *
 * 参考同类成因：Linux Copy Fail（CVE-2026-31431）—— 拷贝长度整数溢出。
 *
 * 注意：需 -fno-sanitize-recover=undefined 使 UBSan 在溢出处中止，
 *       否则 UBSan 默认只打印告警继续执行（见 targets/build.sh）。
 */
#include <stdio.h>
#include <stdlib.h>

static FILE *open_input(int argc, char **argv)
{
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb");
        if (f)
            return f;
    }
    return stdin;
}

int main(int argc, char **argv)
{
    FILE *in = open_input(argc, argv);
    char line[64];

    if (fgets(line, sizeof(line), in) == NULL)
        return 0;

    int count = atoi(line);
    if (count <= 0)
        return 0;

    /* 危险点：32 位有符号乘法溢出（UBSan: signed integer overflow）。
     * count >= 2^29 时 count * 4 溢出 INT_MAX，UBSan 按 -fno-sanitize-recover 直接中止。 */
    int total = count * 4;

    char *buf = (char *)malloc((size_t)total);
    if (!buf)
        return 0;
    for (int i = 0; i < total; i++)
        buf[i] = 0;
    free(buf);
    return 0;
}
