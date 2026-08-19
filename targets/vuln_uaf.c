/* vuln_uaf.c —— 堆释放后使用（heap-use-after-free）
 *
 * 模拟对象生命周期管理：命令流驱动，'f'=释放缓冲区、'w'=写、'r'=读。
 * 漏洞：free() 后未置空指针，后续 'w'/'r' 再次访问 → UAF。
 *
 * 触发输入（stdin 或文件路径）：
 *   printf 'fw' | ./vuln_uaf        # 释放后再写 → heap-use-after-free
 *   printf 'fr' | ./vuln_uaf        # 释放后再读 → heap-use-after-free
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *buf;
    size_t size;
} Holder;

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
    Holder *h = (Holder *)malloc(sizeof(Holder));
    h->buf = (char *)malloc(64);
    h->size = 64;

    int freed = 0;
    int c;
    while ((c = fgetc(in)) != EOF) {
        switch (c) {
        case 'f':                       /* 释放，但未置 h->buf = NULL（漏洞根因） */
            if (!freed) {
                free(h->buf);
                freed = 1;
            }
            break;
        case 'w':                       /* 危险点：写已释放内存 → UAF */
            strcpy(h->buf, "REVFUZZ");
            break;
        case 'r':                       /* 危险点：读已释放内存 → UAF */
            putchar((unsigned char)h->buf[0]);
            break;
        default:
            break;
        }
    }

    if (!freed)
        free(h->buf);
    free(h);
    return 0;
}
