#!/usr/bin/env python3
import json
import sys
import os
import re
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

class StaticAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.functions = []
        self.dangerous_calls = []
        self.input_points = []
        self.dictionary = []
        self.rodata_strings = []  # D3 新增
        
        # 危险 API 特征库
        self.dangerous_apis = {
            'strcpy', 'strncpy', 'strcat', 'sprintf', 'vsprintf', 
            'gets', 'scanf', 'sscanf', 'memcpy', 'memmove',
            'malloc', 'free', 'realloc', 'system', 'popen', 'execve'
        }
        # 输入点特征库
        self.input_apis = {
            'read', 'fread', 'recv', 'recvfrom', 'scanf', 'fscanf',
            'getchar', 'fgetc', 'gets', 'fgets', 'mmap', 'open', 'fopen'
        }

    def build_cfg(self):
        print("[P2 D3] 正在解析函数符号表...")
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
                print(f"[P2 D3] 找到 {len(self.functions)} 个函数")
        except Exception as e:
            print(f"[P2 D3 警告] 解析函数失败: {e}")
        return self.functions

    def locate_sensitive_apis(self):
        print("[P2 D3] 正在扫描危险 API...")
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                dynsym = elffile.get_section_by_name('.dynsym')
                if dynsym:
                    for symbol in dynsym.iter_symbols():
                        if symbol.name in self.dangerous_apis:
                            self.dangerous_calls.append({
                                'function': 'imported',
                                'api': symbol.name,
                                'addr': hex(symbol['st_value']) if symbol['st_value'] else '0x0',
                                'risk': 'high'
                            })
                            self.dictionary.append(symbol.name)
                
                symtab = elffile.get_section_by_name('.symtab')
                if symtab:
                    for symbol in symtab.iter_symbols():
                        if symbol.name in self.dangerous_apis:
                            existing_apis = {item['api'] for item in self.dangerous_calls}
                            if symbol.name not in existing_apis:
                                self.dangerous_calls.append({
                                    'function': 'static',
                                    'api': symbol.name,
                                    'addr': hex(symbol['st_value']),
                                    'risk': 'high'
                                })
                                self.dictionary.append(symbol.name)
                print(f"[P2 D3] 找到 {len(self.dangerous_calls)} 个危险 API 调用")
        except Exception as e:
            print(f"[P2 D3 警告] 扫描危险 API 失败: {e}")
        return self.dangerous_calls

    def analyze_input_points(self):
        print("[P2 D3] 正在识别外部输入点...")
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
                print(f"[P2 D3] 找到 {len(self.input_points)} 个外部输入点")
        except Exception as e:
            print(f"[P2 D3 警告] 分析输入点失败: {e}")
        return self.input_points

    def extract_rodata_strings(self):
        """D3 新增：从 .rodata 段提取所有可打印字符串（长度 >= 4）"""
        print("[P2 D3] 正在从 .rodata 提取内置字符串...")
        try:
            with open(self.binary_path, 'rb') as f:
                elffile = ELFFile(f)
                rodata = elffile.get_section_by_name('.rodata')
                if rodata:
                    data = rodata.data()
                    # 匹配连续的 ASCII 可打印字符（长度至少4），以 \x00 结尾
                    strings = re.findall(rb'([ -~]{4,})\x00', data)
                    for s in strings:
                        try:
                            decoded = s.decode('utf-8', errors='ignore')
                            if len(decoded) >= 4 and decoded not in self.rodata_strings:
                                self.rodata_strings.append(decoded)
                                self.dictionary.append(decoded)  # 直接加入字典
                        except:
                            pass
                    print(f"[P2 D3] 从 .rodata 提取到 {len(self.rodata_strings)} 个内置字符串")
                else:
                    print("[P2 D3] 未找到 .rodata 段")
        except Exception as e:
            print(f"[P2 D3 警告] 提取 .rodata 失败: {e}")
        return self.rodata_strings

    def export_report(self, output_path="analysis.json"):
        # D3：在导出前自动提取 .rodata 字符串
        self.extract_rodata_strings()
        
        report = {
            "target": self.binary_path,
            "functions": self.functions,
            "dangerous_calls": self.dangerous_calls,
            "input_points": self.input_points,
            "dictionary": list(set(self.dictionary)),
            "seeds": []
        }
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"[P2 D3] 增强分析报告已导出至: {output_path}")
        print(f"[P2 D3] 统计: 函数 {len(self.functions)} 个, 危险API {len(self.dangerous_calls)} 个, 输入点 {len(self.input_points)} 个, 字典项 {len(report['dictionary'])} 个 (含.rodata)")
        return report

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 skill1/static_analysis.py <target_binary>")
        sys.exit(1)
    
    binary = sys.argv[1]
    if not os.path.exists(binary):
        print(f"[P2 D3 错误] 目标文件不存在: {binary}")
        sys.exit(1)

    analyzer = StaticAnalyzer(binary)
    analyzer.build_cfg()
    analyzer.locate_sensitive_apis()
    analyzer.analyze_input_points()
    analyzer.export_report("analysis.json")