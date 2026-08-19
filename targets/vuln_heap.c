/* vuln_heap.c —— 堆缓冲区溢出（heap-buffer-overflow）
 *
 * 模拟记录解析：[2 字节小端长度 N][N 字节数据]。
 * 漏洞：分配 N 字节后，写入时多写 1 字节（长度不一致），
 *       当实际读满 N 字节时 buf[N] 越过堆块边界 → 堆溢出。
 *
 * 触发输入（stdin 或文件路径，N=4 时）：
 *   python3 -c "import sys; sys.stdout.buffer.write(b'\x04\x00'+b'A'*4)" | ./vuln_heap
 *
 * 参考同类成因：Linux Copy Fail（CVE-2026-31431）—— 长度计算错误导致 OOB 写。
 */
#include <stdio.h>
#include <stdlib.h>

#define MAX_LEN 512

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
    unsigned char hdr[2];

    if (fread(hdr, 1, sizeof(hdr), in) != sizeof(hdr))
        return 0;

    size_t n = hdr[0] | ((size_t)hdr[1] << 8);   /* 小端长度字段 */
    if (n == 0 || n > MAX_LEN)
        return 0;

    char *buf = (char *)malloc(n);
    if (!buf)
        return 0;

    size_t got = fread(buf, 1, n, in);
    if (got == n) {
        /* 危险点：写 buf[n]，越过 n 字节堆块边界 1 字节 → 堆溢出 */
        buf[n] = '\0';
    }

    free(buf);
    return 0;
}
