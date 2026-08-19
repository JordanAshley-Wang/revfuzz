"""变异器 —— P4 王渊明 负责（D2~D4）。

实现 4 种变异策略（功能要求 #2），按概率调度：
1. 位翻转（bitflip）：30% —— 随机 1~8 个比特做 XOR 翻转；
2. 算术变异（arithmetic）：20% —— 对 1/2/4 字节对齐的小端整数 ±{1,16,32}；
3. 字典替换（dictionary）：25% —— 用字典 token（P2 提取的字符串/magic bytes）插入或覆盖；
4. Havoc：25% —— 2~8 轮堆叠变异，操作池 = 上述操作 + 删段 / 克隆段 / 随机插入。

输出统一截断至 max_len 上限；对空输入/退化缓冲区做防御处理。
dictionary 为空时，字典概率并入 Havoc（保证 4 类分支仍可触发）。

接口契约见 contract.py，签名不可改。
"""
from __future__ import annotations

import random

# ---- 策略被选中的基础概率（合计 1.0；无字典时字典概率并入 Havoc）----
_P_BITFLIP = 0.30
_P_ARITH = 0.20
_P_DICT = 0.25
_P_HAVOC = 0.25

# 算术变异增量集合（±{1,16,32}）
_ARITH_DELTAS = (-32, -16, -1, 1, 16, 32)

# Havoc 每轮可选操作池
_HAVOC_OPS = ("bitflip", "arith", "dict", "delete", "clone", "insert_random")


# ================= 位翻转 =================

def _flip_bits(buf: bytearray, n: int) -> None:
    """随机翻转 n 个比特（XOR 1<<bit）。"""
    if not buf:
        return
    for _ in range(n):
        pos = random.randrange(len(buf))
        buf[pos] ^= 1 << random.randrange(8)


def _bitflip(buf: bytearray) -> None:
    """策略 1：1~8 bit XOR。"""
    _flip_bits(buf, random.randint(1, 8))


# ================= 算术变异 =================

def _arith(buf: bytearray) -> None:
    """策略 2：对 1/2/4 字节对齐的小端整数加减小增量（按位宽回绕）。"""
    if not buf:
        return
    size = random.choice((1, 2, 4))
    if len(buf) < size:
        _flip_bits(buf, 1)
        return
    pos = random.randrange(len(buf) - size + 1)
    val = int.from_bytes(buf[pos:pos + size], "little")
    delta = random.choice(_ARITH_DELTAS)
    val = (val + delta) & ((1 << (8 * size)) - 1)
    buf[pos:pos + size] = val.to_bytes(size, "little")


# ================= 字典替换 =================

def _dict_overwrite(buf: bytearray, tok: bytes) -> None:
    """用字典 token 覆盖随机位置（token 长于缓冲时退化为插入）。"""
    if len(buf) < len(tok):
        _dict_insert(buf, tok)
        return
    pos = random.randrange(len(buf) - len(tok) + 1)
    buf[pos:pos + len(tok)] = tok


def _dict_insert(buf: bytearray, tok: bytes) -> None:
    """在随机位置插入字典 token。"""
    pos = random.randrange(len(buf) + 1)
    buf[pos:pos] = tok


def _dict_op(buf: bytearray, dictionary: list[bytes]) -> None:
    """策略 3：字典插入 / 覆盖各 50%。"""
    tok = random.choice(dictionary)
    if random.random() < 0.5:
        _dict_insert(buf, tok)
    else:
        _dict_overwrite(buf, tok)


# ================= Havoc 原子操作 =================

def _delete_block(buf: bytearray) -> None:
    """删除随机长度的一段字节。"""
    if len(buf) < 2:
        return
    length = random.randint(1, max(1, len(buf) // 2))
    pos = random.randrange(len(buf) - length + 1)
    del buf[pos:pos + length]


def _insert_random(buf: bytearray) -> None:
    """插入 1~8 个随机字节。"""
    length = random.randint(1, 8)
    pos = random.randrange(len(buf) + 1)
    buf[pos:pos] = bytes(random.getrandbits(8) for _ in range(length))


def _clone_block(buf: bytearray) -> None:
    """把随机一段字节复制到随机位置（制造长串/重复输入）。"""
    if len(buf) < 2:
        return
    length = random.randint(1, max(1, len(buf) // 2))
    src = random.randrange(len(buf) - length + 1)
    block = bytes(buf[src:src + length])
    dst = random.randrange(len(buf) + 1)
    buf[dst:dst] = block


def _havoc(buf: bytearray, dictionary: list[bytes]) -> None:
    """策略 4：Havoc —— 2~8 轮堆叠随机变异。

    每轮从操作池随机选一个：bitflip / arith / dict(插入或覆盖) / 删段 / 克隆段 / 随机插入。
    含字典时 dict 操作正常生效，否则退化为随机插入。
    """
    rounds = random.randint(2, 8)
    for _ in range(rounds):
        op = random.choice(_HAVOC_OPS)
        if op == "bitflip":
            _bitflip(buf)
        elif op == "arith":
            _arith(buf)
        elif op == "dict":
            if dictionary:
                _dict_op(buf, dictionary)
            else:
                _insert_random(buf)
        elif op == "delete":
            _delete_block(buf)
        elif op == "clone":
            _clone_block(buf)
        elif op == "insert_random":
            _insert_random(buf)


# ================= 入口 =================

def mutate(seed: bytes, dictionary: list[bytes], max_len: int) -> bytes:
    """对 seed 做一次变异，返回长度不超过 max_len 的新输入。

    - dictionary 来自 P2 静态分析（字符串/magic bytes），可为空；
    - 按 30/20/25/25 概率调度 4 种策略（无字典时字典概率并入 Havoc）；
    - 变异可能插入字节，最终截断到 max_len 上限。
    """
    if not seed:
        seed = b"\x00"
    buf = bytearray(seed)

    roll = random.random()
    if dictionary:
        if roll < _P_BITFLIP:
            _bitflip(buf)
        elif roll < _P_BITFLIP + _P_ARITH:
            _arith(buf)
        elif roll < _P_BITFLIP + _P_ARITH + _P_DICT:
            _dict_op(buf, dictionary)
        else:
            _havoc(buf, dictionary)
    else:
        # 无字典：字典概率并入 Havoc（30/20/50）
        if roll < _P_BITFLIP:
            _bitflip(buf)
        elif roll < _P_BITFLIP + _P_ARITH:
            _arith(buf)
        else:
            _havoc(buf, [])

    if len(buf) > max_len:
        buf = buf[:max_len]
    return bytes(buf)
