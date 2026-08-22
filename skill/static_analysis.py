#!/usr/bin/env python3
"""P2 —— 逆向 Skill 固化：静态分析模块。

将人工漏洞挖掘的逆向流程固化为自动化步骤：
1. 函数定位（ELF 符号表枚举）
2. 敏感 API 识别（objdump 反汇编归因到调用函数，附风险分级）
3. 输入点分析（输入类 API + main 的 argc/argv）
4. 字典提取（.rodata 可打印字符串）
5. 静态边统计（objdump 条件跳转计数，供 edges_total 口径）

对外入口：analyze(target, workdir) -> dict（main.py 集成点）。
产出 analysis.json，schema 见 contract.py ANALYSIS_REQUIRED_KEYS，
另附 "edges_total"（静态总边数，P1 报告覆盖率分母用）。
"""
import json
import os
import re
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


class StaticAnalyzer:
    # sanitizer/afl 运行时函数前缀：风险归因时排除（它们不是目标自身逻辑，
    # 纳入会把 sanitizer 内部对 memcpy 等的调用误记为目标风险，污染调度画像）
    RUNTIME_PREFIXES = ('__asan_', '__ubsan_', '__sanitizer', '__interceptor_',
                        '__msan', '__lsan', '__dfsan', '__sancov', '__afl',
                        '__cmplog', 'asan_')

    # 危险 API 风险分级：(等级, 权重) —— 权重累计为函数 risk_score
    API_RISK = {
        'gets': ('high', 10), 'strcpy': ('high', 8), 'strcat': ('high', 8),
        'sprintf': ('high', 8), 'vsprintf': ('high', 8),
        'system': ('high', 9), 'popen': ('high', 9), 'execve': ('high', 9),
        'scanf': ('medium', 5), 'sscanf': ('medium', 5),
        'memcpy': ('medium', 5), 'memmove': ('medium', 5),
        'free': ('medium', 4), 'realloc': ('medium', 4),
        'strncpy': ('low', 3), 'malloc': ('low', 2),
    }

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.functions = []
        self.dangerous_calls = []
        self.input_points = []
        self.dictionary = []
        self.rodata_strings = []
        self.static_edges = 0  # objdump 静态条件跳转边数（edges_total 口径）

        self.dangerous_apis = set(self.API_RISK)
        # 输入点特征库
        self.input_apis = {
            'read', 'fread', 'recv', 'recvfrom', 'scanf', 'fscanf',
            'getchar', 'fgetc', 'gets', 'fgets', 'mmap', 'open', 'fopen'
        }

    def build_cfg(self):
        print("[P2] 正在解析函数符号表...")
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol['st_info']['type'] == 'STT_FUNC':
                                if symbol.name and symbol['st_value'] != 0:
                                    self.functions.append({
                                        'name': symbol.name,
                                        'addr': symbol['st_value'],
                                        'size': symbol['st_size'],
                                        'risk_score': 0,
                                        'calls': []
                                    })
                seen = set()
                unique_funcs = []
                for func in self.functions:
                    if func['addr'] not in seen:
                        seen.add(func['addr'])
                        unique_funcs.append(func)
                self.functions = unique_funcs
                print(f"[P2] 找到 {len(self.functions)} 个函数")
        except Exception as e:
            print(f"[P2 警告] 解析函数失败: {e}")
        return self.functions

    def analyze_disassembly(self):
        """objdump 反汇编：把危险 API 调用归因到具体函数，并统计静态条件跳转边数。

        - 每个函数命中危险 API 时产出 dangerous_calls 条目（function 为真实调用者），
          并按 API_RISK 权重累计该函数的 risk_score、填充 calls 列表；
          这是 P4 风险加权调度在真实数据下生效的前提。
        - 统计全部条件跳转指令数作为 edges_total（contract 指定口径）。
        成功归因时返回 True；objdump 不可用或无命中时返回 False（调用方走符号表兜底）。
        """
        print("[P2] 正在反汇编分析调用关系与静态边数...")
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary_path],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0 or not proc.stdout:
                print("[P2 警告] objdump 无输出，跳过反汇编分析")
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            print(f"[P2 警告] objdump 调用失败: {e}")
            return False

        func_re = re.compile(r'^[0-9a-f]+\s+<([^>]+)>:')
        insn_re = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')
        target_re = re.compile(r'<([^>]+)>')

        func_calls = {}   # func -> list[(api, addr_int)]（仅危险 API）
        calls_by_func = {}  # func -> set(api)（全部调用，供 functions.calls 展示）
        score_by_func = {}
        edges = 0
        current = None

        for line in proc.stdout.splitlines():
            fm = func_re.match(line)
            if fm:
                current = fm.group(1)
                continue
            im = insn_re.match(line)
            if not im or current is None:
                continue
            addr_s, mnem, rest = im.groups()
            if mnem.startswith('call'):
                tm = target_re.search(rest)
                if not tm:
                    continue
                api = tm.group(1).split('@')[0]  # 去掉 @plt 等后缀
                # ASan/MSan 插桩二进制的库调用被替换为拦截器符号，归一化还原
                if api.startswith('__interceptor_'):
                    api = api[len('__interceptor_'):]
                if current.startswith(self.RUNTIME_PREFIXES):
                    continue  # 运行时函数的调用不归因为目标风险
                calls_by_func.setdefault(current, set()).add(api)
                if api in self.dangerous_apis:
                    func_calls.setdefault(current, []).append((api, int(addr_s, 16)))
                    weight = self.API_RISK.get(api, ('medium', 3))[1]
                    score_by_func[current] = score_by_func.get(current, 0) + weight
            elif mnem.startswith('j') and mnem != 'jmp':
                edges += 1

        self.static_edges = edges
        print(f"[P2] 静态条件跳转边数（edges_total）: {edges}")

        if not func_calls:
            print("[P2] 反汇编未归因到危险调用，回退符号表扫描")
            return False

        for func, apis in func_calls.items():
            for api, addr in apis:
                risk = self.API_RISK.get(api, ('medium', 3))[0]
                self.dangerous_calls.append({
                    'function': func,
                    'api': api,
                    'addr': hex(addr),
                    'risk': risk,
                })
                self.dictionary.append(api)

        by_name = {f['name']: f for f in self.functions}
        for func, score in score_by_func.items():
            if func in by_name:
                by_name[func]['risk_score'] = score
        for func, apis in calls_by_func.items():
            if func in by_name:
                by_name[func]['calls'] = sorted(apis)

        print(f"[P2] 反汇编归因危险调用 {len(self.dangerous_calls)} 处，"
              f"涉及 {len(func_calls)} 个函数")
        return True

    def locate_sensitive_apis(self):
        """符号表兜底扫描（反汇编归因失败时使用）：只知其 import 不知其调用者。"""
        print("[P2] 正在扫描危险 API（符号表兜底）...")
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                dynsym = elffile.get_section_by_name('.dynsym')
                if dynsym:
                    for symbol in dynsym.iter_symbols():
                        if symbol.name in self.dangerous_apis:
                            risk = self.API_RISK.get(symbol.name, ('medium', 3))[0]
                            self.dangerous_calls.append({
                                'function': 'imported',
                                'api': symbol.name,
                                'addr': hex(symbol['st_value']) if symbol['st_value'] else '0x0',
                                'risk': risk,
                            })
                            self.dictionary.append(symbol.name)

                symtab = elffile.get_section_by_name('.symtab')
                if symtab:
                    for symbol in symtab.iter_symbols():
                        if symbol.name in self.dangerous_apis:
                            existing_apis = {item['api'] for item in self.dangerous_calls}
                            if symbol.name not in existing_apis:
                                risk = self.API_RISK.get(symbol.name, ('medium', 3))[0]
                                self.dangerous_calls.append({
                                    'function': 'static',
                                    'api': symbol.name,
                                    'addr': hex(symbol['st_value']),
                                    'risk': risk,
                                })
                                self.dictionary.append(symbol.name)
                print(f"[P2] 找到 {len(self.dangerous_calls)} 个危险 API 调用")
        except Exception as e:
            print(f"[P2 警告] 扫描危险 API 失败: {e}")
        return self.dangerous_calls

    def analyze_input_points(self):
        print("[P2] 正在识别外部输入点...")
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                dynsym = elffile.get_section_by_name('.dynsym')
                if dynsym:
                    for symbol in dynsym.iter_symbols():
                        if symbol.name in self.input_apis:
                            self.input_points.append({
                                'type': 'API',
                                'api': symbol.name,
                                'function': 'imported'
                            })
                            self.dictionary.append(symbol.name)

                symtab = elffile.get_section_by_name('.symtab')
                if symtab:
                    for symbol in symtab.iter_symbols():
                        if symbol.name == 'main' and symbol['st_value'] != 0:
                            self.input_points.append({
                                'type': 'argc_argv',
                                'api': 'main_argv',
                                'function': 'main'
                            })
                            break
                print(f"[P2] 找到 {len(self.input_points)} 个外部输入点")
        except Exception as e:
            print(f"[P2 警告] 分析输入点失败: {e}")
        return self.input_points

    def extract_rodata_strings(self):
        """从 .rodata 段提取所有可打印字符串（长度 >= 4），加入变异字典。"""
        print("[P2] 正在从 .rodata 提取内置字符串...")
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                rodata = elffile.get_section_by_name('.rodata')
                if rodata:
                    data = rodata.data()
                    strings = re.findall(rb'([ -~]{4,})\x00', data)
                    for s in strings:
                        try:
                            decoded = s.decode('utf-8', errors='ignore')
                            if len(decoded) >= 4 and decoded not in self.rodata_strings:
                                self.rodata_strings.append(decoded)
                                self.dictionary.append(decoded)
                        except Exception:
                            pass
                    print(f"[P2] 从 .rodata 提取到 {len(self.rodata_strings)} 个内置字符串")
                else:
                    print("[P2] 未找到 .rodata 段")
        except Exception as e:
            print(f"[P2 警告] 提取 .rodata 失败: {e}")
        return self.rodata_strings

    def export_report(self, output_path="analysis.json"):
        self.extract_rodata_strings()

        report = {
            "target": self.binary_path,
            "functions": self.functions,
            "dangerous_calls": self.dangerous_calls,
            "input_points": self.input_points,
            "dictionary": list(set(self.dictionary)),
            "seeds": [],
            "edges_total": self.static_edges,
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[P2] 分析报告已导出至: {output_path}")
        print(f"[P2] 统计: 函数 {len(self.functions)} 个, 危险API {len(self.dangerous_calls)} 个, "
              f"输入点 {len(self.input_points)} 个, 字典项 {len(report['dictionary'])} 个, "
              f"静态边 {self.static_edges} 条")
        return report


def count_afl_edges(binary_path: str) -> int:
    """从 __sancov_guards 段读取 afl 插桩边总数（每 guard 4 字节对应一条边）。

    afl-clang-fast 的 sancov 插桩为每个基本块边界分配一个 guard，
    段大小 / 4 即精确的静态插桩边数；未插桩或读取失败返回 0。
    """
    try:
        with open(binary_path, 'rb') as f:
            sec = ELFFile(f).get_section_by_name('__sancov_guards')
            if sec is not None:
                return int(sec['sh_size']) // 4
    except Exception:
        pass
    return 0


def analyze(target: str, workdir: str) -> dict:
    """main.py 集成入口：完整静态分析 + 智能种子生成，返回 analysis dict。

    产出（均落在 workdir 下）：
      analysis.json —— contract schema + edges_total
      seeds/        —— SeedGenerator 生成的智能初始种子
      dict.txt      —— 增强变异字典
    """
    os.makedirs(workdir, exist_ok=True)
    report_path = os.path.join(workdir, "analysis.json")

    analyzer = StaticAnalyzer(target)
    analyzer.build_cfg()
    if not analyzer.analyze_disassembly():
        analyzer.locate_sensitive_apis()
    analyzer.analyze_input_points()
    report = analyzer.export_report(report_path)

    # edges_total 口径选择：优先 *_ref 覆盖基准版的 sancov guard 数
    # （目标自身逻辑的插桩边数，不含 sanitizer 注入分支），
    # 其次目标自身的 guard 数（无 ref 时），最后 objdump 条件跳转数兜底
    ref = target + "_ref"
    edges_total = (count_afl_edges(ref) if os.path.isfile(ref) else 0) \
        or count_afl_edges(target) or analyzer.static_edges
    report["edges_total"] = edges_total
    print(f"[P2] edges_total = {edges_total} "
          f"(ref guards={count_afl_edges(ref) if os.path.isfile(ref) else 'N/A'}, "
          f"target guards={count_afl_edges(target)}, objdump={analyzer.static_edges})")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # 智能种子接线（seed_gen）：种子路径写入 report["seeds"] 并回写 analysis.json
    try:
        from skill.seed_gen import SeedGenerator
        gen = SeedGenerator(target, report_path)
        seeds = gen.generate_seeds(os.path.join(workdir, "seeds"))
        gen.generate_dictionary(os.path.join(workdir, "dict.txt"))
        report["seeds"] = seeds
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
    except Exception as e:
        print(f"[P2 警告] 智能种子生成失败（不影响分析结果）: {e}")

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m skill.static_analysis <target_binary> [workdir]")
        sys.exit(1)

    binary = sys.argv[1]
    if not os.path.exists(binary):
        print(f"[P2 错误] 目标文件不存在: {binary}")
        sys.exit(1)

    analyze(binary, sys.argv[2] if len(sys.argv) > 2 else "out")
