#!/usr/bin/env python3
import json
import os
import sys

class SeedGenerator:
    def __init__(self, binary_path, analysis_report_path="analysis.json"):
        self.binary_path = binary_path
        self.report_path = analysis_report_path
        if not os.path.exists(analysis_report_path):
            raise FileNotFoundError(f"找不到分析报告: {analysis_report_path}")
        with open(analysis_report_path, 'r') as f:
            self.report = json.load(f)
        print(f"[P2 D3] 种子生成器加载分析报告成功，共 {len(self.report.get('seeds', []))} 个旧种子路径占位")

    def _smart_strcpy_seeds(self):
        """针对 strcpy 类函数生成更聪明的边界种子"""
        seeds = []
        # 1. 带空字节中断的字符串（绕过 strlen 限制）
        for base_len in [16, 32, 64, 128]:
            payload = b"A" * base_len + b"\x00" + b"B" * base_len
            seeds.append(("strcpy_null", payload))
        # 2. 超长非空字节（堆/栈溢出）
        for length in [64, 128, 256, 512, 1024, 2048]:
            seeds.append((f"strcpy_long_{length}", b"A" * length))
        # 3. 特殊边界：全是 0xff
        for length in [64, 128, 256]:
            seeds.append((f"strcpy_ff_{length}", b"\xff" * length))
        return seeds

    def _smart_format_seeds(self):
        """针对格式化字符串的种子"""
        seeds = []
        fmt_payloads = [
            b"%p" * 10,
            b"%x" * 20,
            b"%n" * 10,
            b"%p" * 5 + b"%n",
            b"%x" * 5 + b"%s" * 5,
        ]
        for i, payload in enumerate(fmt_payloads):
            seeds.append((f"format_{i}", payload))
        return seeds

    def _smart_int_seeds(self):
        """整数解析类目标的经典边界值种子（atoi/strtol 触发整数溢出）"""
        seeds = []
        int_payloads = [
            b"0", b"-1", b"1",
            b"536870912",       # 2^29，×4 溢出 INT_MAX
            b"1073741824",      # 2^30
            b"2147483647",      # INT_MAX
            b"2147483648",      # INT_MAX + 1
            b"-2147483648",     # INT_MIN
            b"4294967295",      # UINT_MAX
            b"9999999999",      # 超 32 位十进制
        ]
        for i, payload in enumerate(int_payloads):
            seeds.append((f"int_boundary_{i}", payload))
        return seeds

    def _smart_path_seeds(self):
        """路径遍历和命令注入种子"""
        seeds = []
        paths = [
            b"../../../../etc/passwd",
            b"../../../../etc/shadow",
            b"/proc/self/environ",
            b"/dev/null",
            b";sh",
            b"|sh",
            b"$(cat /etc/passwd)",
            b"`id`",
        ]
        for i, payload in enumerate(paths):
            seeds.append((f"path_{i}", payload))
        return seeds

    def generate_seeds(self, output_dir="./corpus"):
        os.makedirs(output_dir, exist_ok=True)
        seeds_list = []
        all_smart_seeds = []
        
        # 1. 智能种子：针对 strcpy
        all_smart_seeds.extend(self._smart_strcpy_seeds())
        # 2. 智能种子：格式字符串
        all_smart_seeds.extend(self._smart_format_seeds())
        # 3. 智能种子：整数边界值
        all_smart_seeds.extend(self._smart_int_seeds())
        # 4. 智能种子：路径/命令注入
        all_smart_seeds.extend(self._smart_path_seeds())

        # 写入文件
        for name, data in all_smart_seeds:
            # 文件名包含类型，便于调试
            safe_name = name.replace(" ", "_")
            seed_path = os.path.join(output_dir, f"seed_D3_{safe_name}.bin")
            with open(seed_path, "wb") as f:
                f.write(data)
            seeds_list.append(seed_path)
            print(f"[P2 D3] 生成智能种子: {seed_path} (大小 {len(data)} 字节)")

        # 更新 report 中的种子路径并回写分析报告
        self.report["seeds"] = seeds_list
        with open(self.report_path, "w") as f:
            json.dump(self.report, f, indent=2, default=str)
        print(f"[P2 D3] 共生成 {len(seeds_list)} 个智能种子，已写入 {self.report_path}")
        return seeds_list

    def generate_dictionary(self, output_path="dict.txt"):
        words = set()
        # 从报告中取字典项（现在包含 .rodata 提取的字符串）
        for item in self.report.get("dictionary", []):
            if item and len(item) > 1:
                words.add(str(item))
        # 补充 D3 经典字典
        words.update([
            "A"*256, "B"*512, "C"*1024,
            "%p%p%p%p", "%n%n%n%n", "%s%s%s%s",
            "../../../etc/passwd", "../../../etc/shadow",
            ";sh", "|sh", "$(cat /etc/passwd)",
            "\x00"*16, "\xff"*32, "\x00\x01\x02\x03"
        ])
        with open(output_path, "w") as f:
            for w in sorted(words):
                f.write(w + "\n")
        print(f"[P2 D3] 增强字典已生成: {output_path}, 共 {len(words)} 项 (含.rodata提取词)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m skill.seed_gen <target_binary>")
        sys.exit(1)
    gen = SeedGenerator(sys.argv[1], "analysis.json")
    gen.generate_seeds("./corpus")
    gen.generate_dictionary("dict.txt")
    print("[P2 D3] seed_gen.py 执行完成！")