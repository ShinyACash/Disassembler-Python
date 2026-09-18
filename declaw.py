#!/usr/bin/env python3
"""
declaw - Universal Binary Decompiler & Binary Analysis Engine
Decompiles ELF, PE, and Mach-O executables into clean, human-readable,
idiomatic C code with AST-based control-flow structuring and SSA-like expression propagation.
"""

import sys
import os
import io
import argparse
import re
import struct
import math
import base64
import warnings
from typing import Dict, List, Set, Optional, Tuple, Any
import lief
from capstone import *
from capstone.x86 import *

warnings.filterwarnings('ignore', category=RuntimeWarning)

try:
    from rich.console import Console, Group
    from rich.syntax import Syntax
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.markup import escape
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

REG_64_TO_FAMILY = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
    'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
    'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
    'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
    'r12': 'r12', 'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
    'r13': 'r13', 'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
    'r14': 'r14', 'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
    'r15': 'r15', 'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
}

SYSV_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']


def decode_imm_string(val: int) -> Optional[str]:
    """Decodes integer immediates that encode printable ASCII strings (e.g. 0x4e4957584b434148 -> 'HACKXWIN')."""
    if val < 0:
        val = val & 0xFFFFFFFFFFFFFFFF
    for length in (8, 7, 6, 5, 4, 3):
        mask = (1 << (length * 8)) - 1
        masked = val & mask
        b = masked.to_bytes(length, byteorder='little')
        if all(32 <= c <= 126 for c in b):
            try:
                s = b.decode('ascii')
                s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                return f'"{s}"'
            except Exception:
                pass
    return None


def clean_var_str(op_str: str) -> str:
    """Normalizes stack offsets into clean variable identifiers."""
    op_str = re.sub(r'^(byte|word|dword|qword)\s+ptr\s+', '', op_str.strip())
    m = re.match(r'^\[[re]?bp\s*-\s*(?:0x([0-9a-fA-F]+)|(\d+))\]$', op_str)
    if m:
        offset_hex = m.group(1) if m.group(1) else hex(int(m.group(2)))[2:]
        return f"var_{offset_hex}"
    m = re.match(r'^\[[re]?bp\s*\+\s*(?:0x([0-9a-fA-F]+)|(\d+))\]$', op_str)
    if m:
        offset_hex = m.group(1) if m.group(1) else hex(int(m.group(2)))[2:]
        return f"arg_{offset_hex}"
    m = re.match(r'^\[[re]?sp\s*\+\s*(?:0x([0-9a-fA-F]+)|(\d+))\]$', op_str)
    if m:
        offset_hex = m.group(1) if m.group(1) else hex(int(m.group(2)))[2:]
        return f"var_{offset_hex}"
    if 'fs:0x28' in op_str or ':0x28]' in op_str:
        return "__stack_chk_guard"
    return op_str



def invert_condition(cond: str) -> str:
    """Inverts a logical comparison condition."""
    cond = cond.strip()
    if ' == ' in cond:
        return cond.replace(' == ', ' != ', 1)
    if ' != ' in cond:
        return cond.replace(' != ', ' == ', 1)
    if ' <= ' in cond:
        return cond.replace(' <= ', ' > ', 1)
    if ' >= ' in cond:
        return cond.replace(' >= ', ' < ', 1)
    if ' < ' in cond:
        return cond.replace(' < ', ' >= ', 1)
    if ' > ' in cond:
        return cond.replace(' > ', ' <= ', 1)
    if cond.startswith('!(') and cond.endswith(')'):
        return cond[2:-1]
    return f"!({cond})"


def clean_statement_text(stmt: str) -> str:
    """Cleans up syntax artifacts in generated C statements."""
    stmt = re.sub(r'&("([^"\\]|\\.)*")', r'\1', stmt)
    stmt = re.sub(r'(\w+)\s+js\s+\1', r'\1 < 0', stmt)
    stmt = re.sub(r'(\w+)\s+jns\s+\1', r'\1 >= 0', stmt)
    stmt = re.sub(r'\b==\s*0x2d\b', "== '-'", stmt)
    stmt = re.sub(r'\b!=\s*0x2d\b', "!= '-'", stmt)
    stmt = re.sub(r'\b==\s*0xa\b', "== '\\n'", stmt)
    stmt = re.sub(r'\b!=\s*0xa\b', "!= '\\n'", stmt)
    stmt = re.sub(r'\b==\s*0x0\b', "== 0", stmt)
    stmt = re.sub(r'\b!=\s*0x0\b', "!= 0", stmt)
    if '0xaaaaaaab' in stmt:
        stmt = re.sub(r'\b(var_[0-9a-fA-F]+)\s*-\s*\([^)]*0xaaaaaaab[^)]*\)', r'\1 % 3', stmt)
    return stmt


class BinaryContext:
    """Loads and encapsulates binary sections, symbols, relocations, PLT stubs, and string data."""
    def __init__(self, filename: str):
        self.filename = filename
        self.binary = lief.parse(filename)
        if not self.binary:
            raise ValueError(f"Could not parse binary {filename} with LIEF.")

        self.sections: Dict[str, Dict[str, Any]] = {}
        for s in self.binary.sections:
            if s.size > 0:
                self.sections[s.name] = {
                    'addr': s.virtual_address,
                    'size': s.size,
                    'data': bytes(s.content)
                }

        self.imagebase = 0
        self.entrypoint = self.binary.entrypoint
        if isinstance(self.binary, lief.PE.Binary) and hasattr(self.binary, 'optional_header'):
            self.imagebase = self.binary.optional_header.imagebase
            if self.entrypoint >= self.imagebase:
                self.entrypoint -= self.imagebase

        self.md = self._setup_capstone()
        self.symbol_map: Dict[int, str] = {}
        self.relocs: Dict[int, str] = {}
        self._load_symbols_and_relocs()

    def _setup_capstone(self) -> Cs:
        arch = CS_ARCH_X86
        mode = CS_MODE_64
        arch_name = self.binary.abstract.header.architecture.name if hasattr(self.binary.abstract.header.architecture, 'name') else str(self.binary.abstract.header.architecture)
        if 'X86' in arch_name:
            arch = CS_ARCH_X86
            if hasattr(self.binary.abstract.header, 'is_64'):
                mode = CS_MODE_64 if self.binary.abstract.header.is_64 else CS_MODE_32
            else:
                mode = CS_MODE_64
        elif 'ARM64' in arch_name:
            arch = CS_ARCH_ARM64
            mode = CS_MODE_ARM
        elif 'ARM' in arch_name:
            arch = CS_ARCH_ARM
            mode = CS_MODE_ARM
        elif 'MIPS' in arch_name:
            arch = CS_ARCH_MIPS
            mode = CS_MODE_MIPS32

        md = Cs(arch, mode)
        md.detail = True
        return md

    def _load_symbols_and_relocs(self):
        if isinstance(self.binary, lief.PE.Binary):
            secs = list(self.binary.sections)
            for sym in self.binary.symbols:
                if not sym.name or sym.name.startswith(('.', '/')):
                    continue
                if 1 <= sym.section_idx <= len(secs):
                    sec = secs[sym.section_idx - 1]
                    if sec.name.startswith(('/', '.debug')):
                        continue
                    addr = sec.virtual_address + sym.value
                    self.symbol_map[addr] = sym.name

            for imp in self.binary.imported_functions:
                if imp.name and imp.address > 0:
                    self.symbol_map[imp.address] = imp.name
        else:
            for sym in self.binary.symbols:
                if sym.value > 0 and sym.name:
                    self.symbol_map[sym.value] = sym.name

        if isinstance(self.binary, lief.ELF.Binary):
            for reloc in self.binary.relocations:
                if reloc.has_symbol and reloc.address > 0:
                    self.symbol_map[reloc.address] = reloc.symbol.name
                    self.relocs[reloc.address] = reloc.symbol.name

            # Scan .plt, .plt.sec, .plt.got, __plt sections for jumps
            plt_sections = [s for s in self.binary.sections if s.name in ('.plt', '.plt.sec', '.plt.got', '__plt')]
            for plt_sec in plt_sections:
                plt_bytes = bytes(plt_sec.content)
                for ins in self.md.disasm(plt_bytes, plt_sec.virtual_address):
                    if 'jmp' in ins.mnemonic and ins.operands and ins.operands[0].type == CS_OP_MEM:
                        base = self.md.reg_name(ins.operands[0].mem.base)
                        disp = ins.operands[0].mem.disp
                        if base == 'rip':
                            target = ins.address + ins.size + disp
                        elif base in ('', None) and disp > 0:
                            target = disp
                        else:
                            target = None
                        if target and target in self.relocs:
                            sym_name = self.relocs[target]
                            entry_start = (ins.address // 16) * 16
                            self.symbol_map[entry_start] = sym_name
                            self.symbol_map[ins.address] = sym_name

            # Detect main from _start in ELF
            entry = self.binary.entrypoint
            text = self.binary.get_section('.text')
            if text and text.virtual_address <= entry < text.virtual_address + text.size:
                offset = entry - text.virtual_address
                entry_bytes = bytes(text.content)[offset:offset + 120]
                for ins in self.md.disasm(entry_bytes, entry):
                    if ins.mnemonic == 'mov' and len(ins.operands) == 2:
                        if self.md.reg_name(ins.operands[0].reg) == 'rdi' and ins.operands[1].type == CS_OP_IMM:
                            main_addr = ins.operands[1].imm
                            if text.virtual_address <= main_addr < text.virtual_address + text.size:
                                self.symbol_map[main_addr] = 'main'
                    elif ins.mnemonic == 'lea' and len(ins.operands) == 2:
                        if self.md.reg_name(ins.operands[0].reg) == 'rdi' and ins.operands[1].type == CS_OP_MEM:
                            if self.md.reg_name(ins.operands[1].mem.base) == 'rip':
                                main_addr = ins.address + ins.size + ins.operands[1].mem.disp
                                if text.virtual_address <= main_addr < text.virtual_address + text.size:
                                    self.symbol_map[main_addr] = 'main'

    def read_string(self, abs_addr: int) -> Optional[str]:
        valid_sections = ('.rodata', '.rdata', '__rodata', '__cstring', '.data', '.data.rel.ro')
        if hasattr(self, 'imagebase') and self.imagebase > 0 and abs_addr >= self.imagebase:
            abs_addr -= self.imagebase
        for name, section in self.sections.items():
            if name in valid_sections or 'data' in name or 'ro' in name:
                if section['addr'] <= abs_addr < section['addr'] + section['size']:
                    offset = abs_addr - section['addr']
                    data = section['data'][offset:]
                    null_idx = data.find(b'\x00')
                    raw_str = data[:null_idx] if null_idx != -1 else data[:80]
                    if len(raw_str) >= 1 and all(32 <= b <= 126 or b in (9, 10, 13) for b in raw_str):
                        s = raw_str.decode('ascii', errors='replace')
                        s = s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                        return f'"{s}"'
        return None

    def read_jump_table(self, table_addr: int, max_cases: int = 32) -> List[int]:
        valid_sections = ('.rodata', '.rdata', '__rodata', '.data')
        if hasattr(self, 'imagebase') and self.imagebase > 0 and table_addr >= self.imagebase:
            table_addr -= self.imagebase
        for name, section in self.sections.items():
            if name in valid_sections:
                if section['addr'] <= table_addr < section['addr'] + section['size']:
                    offset = table_addr - section['addr']
                    data = section['data'][offset:]
                    entries = []
                    for i in range(max_cases):
                        if (i + 1) * 8 > len(data):
                            break
                        ptr = struct.unpack('<Q', data[i * 8:(i + 1) * 8])[0]
                        if any(s['addr'] <= ptr < s['addr'] + s['size'] for sname, s in self.sections.items() if 'text' in sname or 'code' in sname):
                            entries.append(ptr)
                        else:
                            break
                    if len(entries) >= 2:
                        return entries
        return []


class ILBlock:
    """Represents a Basic Block with lifted statements and control-flow edges."""
    def __init__(self, start_addr: int):
        self.start_addr = start_addr
        self.end_addr = start_addr
        self.instructions: List[Any] = []
        self.statements: List[str] = []
        self.successors: List['ILBlock'] = []
        self.predecessors: List['ILBlock'] = []
        self.condition: Optional[str] = None
        self.jump_type: Optional[str] = None
        self.switch_expr: Optional[str] = None
        self.switch_cases: Dict[int, int] = {}
        self.raw_jump_target: Optional[str] = None


class FunctionFinder:
    """Discovers function boundaries cleanly, avoiding accidental function merging."""
    @staticmethod
    def get_code_sections(ctx: BinaryContext) -> List[Any]:
        code_sections = []
        for s in ctx.binary.sections:
            if s.size == 0:
                continue
            is_exec = False
            if hasattr(lief.ELF, 'SECTION_FLAGS') and isinstance(ctx.binary, lief.ELF.Binary):
                is_exec = s.has(lief.ELF.SECTION_FLAGS.EXECINSTR)
            elif hasattr(lief.PE, 'SECTION_CHARACTERISTICS') and isinstance(ctx.binary, lief.PE.Binary):
                is_exec = s.has(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
            elif hasattr(lief.MachO, 'SECTION_FLAGS') and isinstance(ctx.binary, lief.MachO.Binary):
                is_exec = s.has(lief.MachO.SECTION_FLAGS.SOME_INSTRUCTIONS)
            if is_exec and s.name not in ('.plt', '.plt.sec', '__plt'):
                code_sections.append(s)

        if not code_sections:
            for s in ctx.binary.sections:
                if s.name in ('.text', '__text', 'CODE'):
                    code_sections.append(s)
        return code_sections

    @staticmethod
    def find_functions(ctx: BinaryContext) -> List[Tuple[int, int, str]]:
        code_sections = FunctionFinder.get_code_sections(ctx)
        starts: Set[int] = set()

        if ctx.entrypoint > 0:
            starts.add(ctx.entrypoint)

        for addr in ctx.symbol_map:
            if any(s.virtual_address <= addr < s.virtual_address + s.size for s in code_sections):
                starts.add(addr)

        endbr_followers: Set[int] = set()

        for s in code_sections:
            bytes_data = bytes(s.content)
            base = s.virtual_address
            end = base + s.size
            starts.add(base)

            ins_list = list(ctx.md.disasm(bytes_data, base))
            for i, ins in enumerate(ins_list):
                if ins.mnemonic in ('call', 'bl'):
                    try:
                        target = int(ins.op_str.split(',')[0], 16)
                        if base <= target < end:
                            starts.add(target)
                    except ValueError:
                        pass
                elif ins.mnemonic in ('endbr64', 'endbr32'):
                    starts.add(ins.address)
                    endbr_followers.add(ins.address + ins.size)
                elif ins.mnemonic == 'push' and ins.op_str in ('rbp', 'ebp'):
                    nxt = ins_list[i + 1] if i + 1 < len(ins_list) else None
                    if nxt and nxt.mnemonic == 'mov' and nxt.op_str in ('rbp, rsp', 'ebp, esp'):
                        if ins.address not in endbr_followers:
                            j = i - 1
                            while j >= 0 and ins_list[j].mnemonic in ('nop', 'endbr64', 'endbr32'):
                                j -= 1
                            prev_m = ins_list[j].mnemonic if j >= 0 else None
                            if j < 0 or prev_m in ('ret', 'jmp', 'hlt', 'ud2', 'int3'):
                                starts.add(ins.address)

        # Remove redundant addresses right after endbr64
        starts = starts - endbr_followers

        # Filter out candidate starts that fall strictly inside known ELF function symbols
        if isinstance(ctx.binary, lief.ELF.Binary):
            for sym in ctx.binary.symbols:
                if sym.type == lief.ELF.Symbol.TYPE.FUNC and sym.value > 0 and sym.size > 0:
                    starts = {s for s in starts if s == sym.value or not (sym.value < s < sym.value + sym.size)}
        sorted_starts = sorted(list(starts))
        functions = []
        for i, start_addr in enumerate(sorted_starts):
            sec = next((s for s in code_sections if s.virtual_address <= start_addr < s.virtual_address + s.size), None)
            if not sec:
                continue
            sec_end = sec.virtual_address + sec.size
            next_start = sorted_starts[i + 1] if i + 1 < len(sorted_starts) and sorted_starts[i + 1] < sec_end else sec_end
            end_addr = next_start
            func_name = ctx.symbol_map.get(start_addr, f"func_{hex(start_addr)}")
            functions.append((start_addr, end_addr, func_name))

        return functions


class InstructionLifter:
    """Lifts raw Capstone assembly into high-level C expressions with argument folding and dead code stripping."""
    @staticmethod
    def lift(ctx: BinaryContext, func_addr: int, func_end_addr: int) -> Optional[List[ILBlock]]:
        sec = next((s for s in ctx.sections.values() if s['addr'] <= func_addr < s['addr'] + s['size']), None)
        if not sec:
            return None

        offset = func_addr - sec['addr']
        end_offset = func_end_addr - sec['addr']
        func_bytes = sec['data'][offset:end_offset]

        instructions = list(ctx.md.disasm(func_bytes, func_addr))
        if not instructions:
            return None

        leaders: Set[int] = set([func_addr])
        jump_table_info: Dict[int, Tuple[str, List[int]]] = {}

        for ins in instructions:
            m = ins.mnemonic
            if m in ('jmp', 'b') and ins.operands and ins.operands[0].type == CS_OP_MEM:
                mem = ins.operands[0].mem
                if mem.disp > 0 and mem.index != 0:
                    entries = ctx.read_jump_table(mem.disp)
                    if entries:
                        index_reg = ctx.md.reg_name(mem.index)
                        jump_table_info[ins.address] = (index_reg, entries)
                        for target in entries:
                            if func_addr <= target < func_end_addr:
                                leaders.add(target)
            elif m.startswith('j') or m.startswith('b') or m in ('call', 'bl'):
                try:
                    target = int(ins.op_str.split(',')[0], 16)
                    if func_addr <= target < func_end_addr:
                        leaders.add(target)
                except ValueError:
                    pass
            if m.startswith('j') or m.startswith('b') or m in ('call', 'bl', 'ret'):
                next_addr = ins.address + ins.size
                if func_addr <= next_addr < func_end_addr:
                    leaders.add(next_addr)

        blocks: List[ILBlock] = []
        block_map: Dict[int, ILBlock] = {}
        cur_block: Optional[ILBlock] = None

        for ins in instructions:
            if ins.address in leaders:
                cur_block = ILBlock(ins.address)
                blocks.append(cur_block)
                block_map[ins.address] = cur_block
            if cur_block:
                cur_block.instructions.append(ins)
                cur_block.end_addr = ins.address + ins.size

        for i, b in enumerate(blocks):
            if not b.instructions:
                continue
            last_ins = b.instructions[-1]
            m = last_ins.mnemonic
            nxt = blocks[i + 1] if i + 1 < len(blocks) else None

            if last_ins.address in jump_table_info:
                b.jump_type = 'switch'
                reg, targets = jump_table_info[last_ins.address]
                b.switch_expr = reg
                for c_idx, tgt in enumerate(targets):
                    b.switch_cases[c_idx] = tgt
                    if tgt in block_map:
                        target_b = block_map[tgt]
                        if target_b not in b.successors:
                            b.successors.append(target_b)
            elif m == 'ret':
                b.jump_type = 'ret'
            elif m in ('jmp', 'b'):
                b.jump_type = 'jmp'
                try:
                    tgt = int(last_ins.op_str.split(',')[0], 16)
                    if tgt in block_map:
                        b.successors.append(block_map[tgt])
                    else:
                        b.raw_jump_target = hex(tgt)
                except ValueError:
                    b.raw_jump_target = last_ins.op_str
            elif m.startswith('j') or m.startswith('b'):
                b.jump_type = 'cond'
                try:
                    tgt = int(last_ins.op_str.split(',')[0], 16)
                    if tgt in block_map:
                        b.successors.append(block_map[tgt])
                    if nxt:
                        b.successors.append(nxt)
                except ValueError:
                    pass
            else:
                b.jump_type = 'fall'
                if nxt:
                    b.successors.append(nxt)

            for s in b.successors:
                s.predecessors.append(b)

        canary_regs: Set[str] = set()
        canary_var = None

        for b in blocks:
            reg_state: Dict[str, str] = {}
            pushed_args: List[str] = []
            statements: List[str] = []
            last_cmp: Optional[Tuple[str, str, str]] = None
            last_call_expr: Optional[str] = None

            for ins_idx, ins in enumerate(b.instructions):
                m = ins.mnemonic
                op_str = ins.op_str

                if m in ('endbr64', 'endbr32', 'nop'):
                    continue
                if m == 'lea' and op_str.startswith('ecx,') and '[esp' in op_str:
                    continue
                if m == 'and' and op_str.startswith('esp,'):
                    continue
                if m == 'push' and (op_str in ('rbp', 'ebp', 'r12', 'r13', 'r14', 'r15', 'rbx', 'ecx') or 'ecx - 4' in op_str):
                    continue
                if m == 'pop' and op_str in ('rbp', 'ebp', 'r12', 'r13', 'r14', 'r15', 'rbx', 'ecx'):
                    continue
                if m == 'mov' and op_str in ('rbp, rsp', 'ebp, esp'):
                    continue
                if m == 'sub' and (op_str.startswith('rsp, ') or op_str.startswith('esp, ')):
                    pushed_args.clear()
                    continue
                if m == 'leave':
                    continue

                # Stack canary setup
                if m == 'mov' and ('fs:0x28' in op_str or ':0x28]' in op_str):
                    parts = op_str.split(',')
                    dest_reg = parts[0].strip()
                    fam = REG_64_TO_FAMILY.get(dest_reg)
                    if fam:
                        canary_regs.add(fam)
                        reg_state[fam] = '__stack_chk_guard'
                    continue
                if m == 'mov':
                    parts = op_str.split(',')
                    if len(parts) == 2:
                        src_reg = parts[1].strip()
                        src_fam = REG_64_TO_FAMILY.get(src_reg)
                        if src_fam and src_fam in canary_regs:
                            canary_var = clean_var_str(parts[0].strip())
                            continue

                # Stack canary check at epilogue
                if canary_var and (canary_var in op_str or 'fs:0x28' in op_str or ':0x28]' in op_str):
                    if m in ('xor', 'sub', 'cmp') or (m == 'mov' and 'fs:0x28' in op_str):
                        continue

                # Resolve operands
                resolved_ops = []
                if hasattr(ins, 'operands') and ins.operands:
                    for op in ins.operands:
                        if op.type == CS_OP_REG:
                            r_name = ctx.md.reg_name(op.reg)
                            resolved_ops.append(r_name)
                        elif op.type == CS_OP_IMM:
                            imm = op.imm
                            if imm == 0:
                                resolved_ops.append("0")
                            elif imm in ctx.symbol_map:
                                resolved_ops.append(ctx.symbol_map[imm])
                            else:
                                s = ctx.read_string(imm)
                                if s:
                                    resolved_ops.append(s)
                                else:
                                    imm_str = decode_imm_string(imm)
                                    if imm_str:
                                        resolved_ops.append(imm_str)
                                    elif -9 <= imm <= 9:
                                        resolved_ops.append(str(imm))
                                    else:
                                        resolved_ops.append(hex(imm))
                        elif op.type == CS_OP_MEM:
                            base = ctx.md.reg_name(op.mem.base) if op.mem.base != 0 else ""
                            index = ctx.md.reg_name(op.mem.index) if op.mem.index != 0 else ""
                            scale = op.mem.scale
                            disp = op.mem.disp
                            seg = ctx.md.reg_name(op.mem.segment) if hasattr(op.mem, 'segment') and op.mem.segment != 0 else ""

                            if seg == 'fs':
                                resolved_ops.append(f"[fs:{hex(disp)}]")
                            elif base == 'rip':
                                target = ins.address + ins.size + disp
                                if target in ctx.symbol_map:
                                    resolved_ops.append(ctx.symbol_map[target])
                                else:
                                    s = ctx.read_string(target)
                                    resolved_ops.append(s if s else f"g_data_{hex(target)}")
                            elif base in ('rsp', 'rbp', 'esp', 'ebp'):
                                if disp == 0:
                                    resolved_ops.append(f"[{base}]")
                                elif disp > 0:
                                    resolved_ops.append(clean_var_str(f"[{base} + {hex(disp)}]"))
                                else:
                                    if index:
                                        resolved_ops.append(f"var_{hex(-disp)[2:]}[{index}]")
                                    else:
                                        resolved_ops.append(clean_var_str(f"[{base} - {hex(-disp)}]"))
                            elif base and index:
                                if scale > 1:
                                    resolved_ops.append(f"{base}[{index} * {scale}]")
                                else:
                                    resolved_ops.append(f"{base}[{index}]")
                            elif index and disp:
                                sym = ctx.symbol_map.get(disp, f"g_data_{hex(disp)}")
                                resolved_ops.append(f"{sym}[{index}]")
                            elif not base and not index and disp:
                                if disp in ctx.symbol_map:
                                    resolved_ops.append(ctx.symbol_map[disp])
                                else:
                                    s = ctx.read_string(disp)
                                    resolved_ops.append(s if s else f"g_data_{hex(disp)}")
                            elif base:
                                resolved_ops.append(f"*{base}" if disp == 0 else f"*({base} + {hex(disp)})")
                            else:
                                resolved_ops.append(f"[{hex(disp)}]")
                        else:
                            resolved_ops.append("UNKNOWN")
                else:
                    parts = [p.strip() for p in op_str.split(',')]
                    resolved_ops = [clean_var_str(p) for p in parts if p]

                # Lift semantics
                if m in ('mov', 'movzx', 'movsx', 'movsxd', 'movabs') and len(resolved_ops) == 2:
                    dest, src = resolved_ops
                    src_fam = REG_64_TO_FAMILY.get(src)
                    src_val = reg_state.get(src_fam, src) if src_fam else src
                    dest_fam = REG_64_TO_FAMILY.get(dest)
                    if dest_fam:
                        reg_state[dest_fam] = src_val
                    else:
                        statements.append(f"{dest} = {src_val};")

                elif m == 'lea' and len(resolved_ops) == 2:
                    dest, src = resolved_ops
                    dest_fam = REG_64_TO_FAMILY.get(dest)
                    if src.startswith('var_') or src.startswith('arg_') or src.startswith('stack_'):
                        addr_val = f"&{src}"
                    elif src.startswith('*'):
                        addr_val = src[1:]
                    else:
                        addr_val = f"&{src}" if not src.startswith('&') else src

                    if dest_fam:
                        reg_state[dest_fam] = addr_val
                    else:
                        statements.append(f"{dest} = {addr_val};")

                elif m in ('add', 'sub') and len(resolved_ops) == 2:
                    dest, src = resolved_ops
                    if dest in ('rsp', 'esp'):
                        continue
                    src_fam = REG_64_TO_FAMILY.get(src)
                    src_val = reg_state.get(src_fam, src) if src_fam else src
                    dest_fam = REG_64_TO_FAMILY.get(dest)
                    op_sym = '+' if m == 'add' else '-'

                    if dest_fam:
                        prev = reg_state.get(dest_fam, dest)
                        reg_state[dest_fam] = f"({prev} {op_sym} {src_val})"
                    else:
                        if src_val in ('1', '0x1'):
                            statements.append(f"{dest}++;" if m == 'add' else f"{dest}--;")
                        else:
                            statements.append(f"{dest} {op_sym}= {src_val};")

                elif m == 'inc' and len(resolved_ops) == 1:
                    statements.append(f"{resolved_ops[0]}++;")
                elif m == 'dec' and len(resolved_ops) == 1:
                    statements.append(f"{resolved_ops[0]}--;")

                elif m == 'xor' and len(resolved_ops) == 2:
                    dest, src = resolved_ops
                    dest_fam = REG_64_TO_FAMILY.get(dest)
                    if dest == src:
                        if dest_fam:
                            reg_state[dest_fam] = "0"
                        else:
                            statements.append(f"{dest} = 0;")
                    else:
                        src_fam = REG_64_TO_FAMILY.get(src)
                        src_val = reg_state.get(src_fam, src) if src_fam else src
                        if dest_fam:
                            prev = reg_state.get(dest_fam, dest)
                            reg_state[dest_fam] = f"({prev} ^ {src_val})"
                        else:
                            statements.append(f"{dest} ^= {src_val};")

                elif m in ('and', 'or', 'shl', 'shr') and len(resolved_ops) == 2:
                    dest, src = resolved_ops
                    src_fam = REG_64_TO_FAMILY.get(src)
                    src_val = reg_state.get(src_fam, src) if src_fam else src
                    dest_fam = REG_64_TO_FAMILY.get(dest)
                    sym_map = {'and': '&', 'or': '|', 'shl': '<<', 'shr': '>>'}
                    op_sym = sym_map[m]
                    if dest_fam:
                        prev = reg_state.get(dest_fam, dest)
                        reg_state[dest_fam] = f"({prev} {op_sym} {src_val})"
                    else:
                        statements.append(f"{dest} {op_sym}= {src_val};")

                elif m in ('cmp', 'test') and len(resolved_ops) == 2:
                    op1, op2 = resolved_ops
                    op1_fam = REG_64_TO_FAMILY.get(op1)
                    op2_fam = REG_64_TO_FAMILY.get(op2)
                    v1 = reg_state.get(op1_fam, op1) if op1_fam else op1
                    v2 = reg_state.get(op2_fam, op2) if op2_fam else op2
                    last_cmp = (v1, v2, m)

                elif m == 'push' and len(resolved_ops) == 1:
                    val = resolved_ops[0]
                    fam = REG_64_TO_FAMILY.get(val)
                    if fam and fam in reg_state:
                        val = reg_state[fam]
                    if val not in ('ebp', 'ecx', 'rbp') and not (val.startswith('[ecx') or val.startswith('[rcx')):
                        pushed_args.append(val)

                elif m == 'add' and 'esp' in op_str:
                    pushed_args.clear()

                elif m in ('call', 'bl'):
                    target_str = resolved_ops[0] if resolved_ops else "unknown_func"
                    try:
                        target_addr = int(target_str, 16)
                        target_name = ctx.symbol_map.get(target_addr, f"func_{hex(target_addr)}")
                    except ValueError:
                        target_name = target_str

                    args = []
                    for r in SYSV_ARG_REGS:
                        if r in reg_state:
                            args.append(reg_state[r])
                        else:
                            break

                    if not args and pushed_args:
                        args = list(reversed(pushed_args))
                        pushed_args.clear()

                    call_expr = f"{target_name}({', '.join(args)})"
                    last_call_expr = call_expr

                    for r in ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'r10', 'r11'):
                        reg_state.pop(r, None)

                    next_ins = b.instructions[ins_idx + 1] if ins_idx + 1 < len(b.instructions) else None
                    if next_ins and next_ins.mnemonic in ('mov', 'movzx', 'movsx', 'movsxd') and any(reg in next_ins.op_str.split(',')[1] for reg in ('rax', 'eax')):
                        reg_state['rax'] = call_expr
                    elif target_name in ('__stack_chk_fail',):
                        b.jump_type = 'canary_fail'
                    elif target_name in ('exit', 'abort'):
                        statements.append(f"{call_expr};")
                    else:
                        reg_state['rax'] = call_expr
                        statements.append(f"{call_expr};")

                elif m in ('jmp', 'b'):
                    target_name = None
                    if resolved_ops and resolved_ops[0] in ctx.symbol_map.values():
                        target_name = resolved_ops[0]
                    else:
                        try:
                            target_addr = int(resolved_ops[0], 16) if resolved_ops else None
                            if target_addr and target_addr in ctx.symbol_map:
                                target_name = ctx.symbol_map[target_addr]
                        except ValueError:
                            pass

                    if target_name and target_name not in ('__stack_chk_fail',):
                        args = [reg_state[r] for r in SYSV_ARG_REGS if r in reg_state]
                        if not args and pushed_args:
                            args = list(reversed(pushed_args))
                            pushed_args.clear()
                        statements.append(f"{target_name}({', '.join(args)});")
                        statements.append("return;")
                        b.jump_type = 'ret'

                elif m == 'ret':
                    ret_val = reg_state.get('rax')
                    if ret_val:
                        statements.append(f"return {ret_val};")
                    else:
                        statements.append("return;")

            # Build condition string
            if b.jump_type == 'cond' and len(b.instructions) > 0:
                last_ins = b.instructions[-1]
                c_mnem = last_ins.mnemonic
                if last_cmp:
                    v1, v2, cmp_type = last_cmp
                    cond_map = {
                        'je': f"{v1} == {v2}", 'jz': f"{v1} == {v2}",
                        'jne': f"{v1} != {v2}", 'jnz': f"{v1} != {v2}",
                        'jg': f"{v1} > {v2}", 'jge': f"{v1} >= {v2}",
                        'jl': f"{v1} < {v2}", 'jle': f"{v1} <= {v2}",
                        'ja': f"(unsigned){v1} > {v2}", 'jae': f"(unsigned){v1} >= {v2}",
                        'jb': f"(unsigned){v1} < {v2}", 'jbe': f"(unsigned){v1} <= {v2}",
                    }
                    if cmp_type == 'test' and v1 == v2:
                        if c_mnem in ('jz', 'je'):
                            b.condition = f"{v1} == 0"
                        elif c_mnem in ('jnz', 'jne'):
                            b.condition = f"{v1} != 0"
                        elif c_mnem == 'jle':
                            b.condition = f"{v1} <= 0"
                        elif c_mnem == 'jl':
                            b.condition = f"{v1} < 0"
                        elif c_mnem == 'jg':
                            b.condition = f"{v1} > 0"
                        elif c_mnem == 'jge':
                            b.condition = f"{v1} >= 0"
                        else:
                            b.condition = cond_map.get(c_mnem, f"{v1} {c_mnem} {v2}")
                    else:
                        b.condition = cond_map.get(c_mnem, f"{v1} {c_mnem} {v2}")
                else:
                    b.condition = c_mnem

                # Fold call into condition if condition tests return value
                if b.condition and last_call_expr:
                    if re.search(r'\b(rax|eax|al)\b', b.condition):
                        b.condition = re.sub(r'\b(rax|eax|al)\b', last_call_expr, b.condition)
                        if statements and statements[-1].strip() == f"{last_call_expr};":
                            statements.pop()

                if b.condition:
                    b.condition = clean_statement_text(b.condition)

            b.statements = statements

        return blocks


class ASTStructurer:
    """Transforms raw BasicBlocks into structured C control flow (loops, if-else, switches)."""
    @staticmethod
    def find_reachable(start_block: ILBlock, stop_at: Optional[ILBlock] = None) -> Set[int]:
        visited: Set[int] = set()
        queue = [start_block]
        while queue:
            curr = queue.pop(0)
            if curr.start_addr in visited or (stop_at and curr.start_addr == stop_at.start_addr):
                continue
            visited.add(curr.start_addr)
            for s in curr.successors:
                if s.start_addr not in visited and (not stop_at or s.start_addr != stop_at.start_addr):
                    queue.append(s)
        return visited

    @staticmethod
    def decompile(ctx: BinaryContext, func_addr: int, func_end_addr: int) -> str:
        blocks = InstructionLifter.lift(ctx, func_addr, func_end_addr)
        if not blocks:
            return "// (empty function)\n"

        func_name = ctx.symbol_map.get(func_addr, f"func_{hex(func_addr)}")
        block_map = {b.start_addr: b for b in blocks}

        # Collapse repetitive zeroing into clean memset
        for b in blocks:
            new_stmts = []
            zero_vars = []
            for s in b.statements:
                m = re.match(r'^(var_[0-9a-fA-F]+)\s*=\s*0;$', s)
                if m:
                    zero_vars.append(m.group(1))
                else:
                    if len(zero_vars) >= 4:
                        new_stmts.append(f"memset(&{zero_vars[0]}, 0, sizeof({zero_vars[0]})); /* zeroed {len(zero_vars)*8} bytes */")
                    else:
                        for v in zero_vars:
                            new_stmts.append(f"{v} = 0;")
                    zero_vars = []
                    new_stmts.append(s)
            if len(zero_vars) >= 4:
                new_stmts.append(f"memset(&{zero_vars[0]}, 0, sizeof({zero_vars[0]})); /* zeroed {len(zero_vars)*8} bytes */")
            else:
                for v in zero_vars:
                    new_stmts.append(f"{v} = 0;")
            b.statements = new_stmts

        # Natural loops (back-edges: target <= source)
        loops = []
        for b in blocks:
            for s in b.successors:
                if s.start_addr <= b.start_addr:
                    h, l = s.start_addr, b.start_addr
                    body = set([h, l])
                    work = [l]
                    while work:
                        curr = work.pop()
                        if curr in block_map:
                            for p in block_map[curr].predecessors:
                                if p.start_addr not in body:
                                    body.add(p.start_addr)
                                    work.append(p.start_addr)
                    exits = set()
                    for b_addr in body:
                        if b_addr in block_map:
                            for succ in block_map[b_addr].successors:
                                if succ.start_addr not in body:
                                    exits.add(succ.start_addr)
                    loops.append((h, l, body, exits))

        # Classify loops
        loop_info_map: Dict[int, Dict[str, Any]] = {}
        for h, l, body, exits in loops:
            h_block = block_map[h]
            l_block = block_map[l]
            step_str = None
            loop_var = None

            for s in l_block.statements:
                m = re.match(r'^(var_[0-9a-fA-F]+|\w+)\+\+;$', s)
                if m:
                    loop_var, step_str = m.group(1), f"{m.group(1)}++"
                m2 = re.match(r'^(var_[0-9a-fA-F]+|\w+)\s*\+=\s*(\d+);$', s)
                if m2:
                    loop_var, step_str = m2.group(1), f"{m2.group(1)} += {m2.group(2)}"

            cond_str, init_str, exit_target = None, None, None
            if loop_var:
                for b_addr in body:
                    bb = block_map[b_addr]
                    if bb.condition and loop_var in bb.condition:
                        cond_str = bb.condition
                        for succ in bb.successors:
                            if succ.start_addr in exits:
                                exit_target = succ.start_addr
                        break
                for p in h_block.predecessors:
                    if p.start_addr not in body:
                        for s in reversed(p.statements):
                            m_init = re.match(rf'^{loop_var}\s*=\s*([^;]+);$', s)
                            if m_init:
                                init_str = f"{loop_var} = {m_init.group(1)}"
                                break

            if loop_var and cond_str and step_str:
                loop_info_map[h] = {
                    'type': 'for', 'init': init_str or f"{loop_var} = 0",
                    'cond': cond_str, 'step': step_str, 'body': body,
                    'exits': exits, 'latch': l
                }
            elif h_block.jump_type == 'cond' and len(h_block.successors) == 2:
                s0, s1 = h_block.successors[0], h_block.successors[1]
                c = invert_condition(h_block.condition) if s0.start_addr in exits else h_block.condition
                loop_info_map[h] = {
                    'type': 'while', 'cond': c, 'body': body,
                    'exits': exits, 'latch': l
                }
            else:
                loop_info_map[h] = {
                    'type': 'while_1', 'cond': '1', 'body': body,
                    'exits': exits, 'latch': l
                }

        processed: Set[int] = set()
        lines: List[str] = []
        pad = "    "

        # Collect local variables and infer types
        all_vars: Dict[str, str] = {}
        for b in blocks:
            for s in b.statements:
                for v in re.findall(r'\b(var_[0-9a-fA-F]+)\b', s):
                    if v not in all_vars:
                        all_vars[v] = 'int'

                m_buf = re.search(r'\b(fgets|read|read_input)\s*\(\s*&(var_[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+|\d+)', s)
                if m_buf:
                    var_name = m_buf.group(2)
                    size_val = int(m_buf.group(3), 0)
                    all_vars[var_name] = f"char {var_name}[{size_val}]"

                m_set = re.search(r'memset\s*\(\s*&(var_[0-9a-fA-F]+).*?sizeof\(\w+\)\);\s*/\*\s*zeroed\s+(\d+)\s*bytes', s)
                if m_set:
                    var_name = m_set.group(1)
                    size_val = int(m_set.group(2))
                    all_vars[var_name] = f"char {var_name}[{size_val}]"

                if re.search(r'\b(var_[0-9a-fA-F]+)\s*=\s*fopen\b', s):
                    m_f = re.search(r'\b(var_[0-9a-fA-F]+)\s*=\s*fopen\b', s)
                    if m_f:
                        all_vars[m_f.group(1)] = f"FILE *{m_f.group(1)} = NULL"

        # Emit Function Signature
        if func_name == 'main':
            lines.append("int main(int argc, char **argv) {")
        else:
            lines.append(f"int {func_name}() {{")

        # Declare local variables cleanly at the top
        if all_vars:
            for v_name, v_decl in sorted(all_vars.items()):
                if ' ' in v_decl:
                    lines.append(f"{pad}{v_decl};")
                else:
                    lines.append(f"{pad}int {v_name} = 0;")
            lines.append("")

        i = 0
        while i < len(blocks):
            b = blocks[i]
            if b.start_addr in processed:
                i += 1
                continue

            # Case: Loop Header
            if b.start_addr in loop_info_map:
                linfo = loop_info_map[b.start_addr]
                l_type = linfo['type']
                l_body = linfo['body']
                l_exits = linfo['exits']

                if l_type == 'for':
                    lines.append(f"{pad}for ({linfo['init']}; {linfo['cond']}; {linfo['step']}) {{")
                elif l_type == 'while':
                    lines.append(f"{pad}while ({linfo['cond']}) {{")
                else:
                    lines.append(f"{pad}while (1) {{")

                body_blocks = [block_map[addr] for addr in sorted(list(l_body))]
                for bb in body_blocks:
                    if bb.start_addr in processed:
                        continue
                    for s in bb.statements:
                        if l_type == 'for' and (s == f"{linfo['step']};" or s.startswith(linfo['step'])):
                            continue
                        lines.append(f"{pad}    {clean_statement_text(s)}")

                    if bb.jump_type == 'switch':
                        lines.append(f"{pad}    switch ({bb.switch_expr}) {{")
                        for c_val, tgt in sorted(bb.switch_cases.items()):
                            lines.append(f"{pad}        case {c_val}:")
                            tgt_b = block_map.get(tgt)
                            if tgt_b:
                                for s in tgt_b.statements:
                                    lines.append(f"{pad}            {clean_statement_text(s)}")
                                lines.append(f"{pad}            break;")
                                processed.add(tgt)
                        lines.append(f"{pad}    }}")
                    elif bb.jump_type == 'cond':
                        t = bb.successors[0].start_addr if len(bb.successors) > 0 else None
                        if t in l_exits:
                            lines.append(f"{pad}    if ({bb.condition}) break;")
                        elif t == linfo['latch']:
                            lines.append(f"{pad}    if ({bb.condition}) continue;")
                    elif bb.jump_type == 'jmp':
                        t = bb.successors[0].start_addr if len(bb.successors) > 0 else None
                        if t in l_exits:
                            lines.append(f"{pad}    break;")

                    processed.add(bb.start_addr)

                lines.append(f"{pad}}}")
                i += 1
                continue

            # Case: Switch Table
            if b.jump_type == 'switch':
                for s in b.statements:
                    lines.append(f"{pad}{clean_statement_text(s)}")
                lines.append(f"{pad}switch ({b.switch_expr}) {{")
                for c_val, tgt in sorted(b.switch_cases.items()):
                    lines.append(f"{pad}    case {c_val}:")
                    tgt_b = block_map.get(tgt)
                    if tgt_b:
                        for s in tgt_b.statements:
                            lines.append(f"{pad}        {clean_statement_text(s)}")
                        lines.append(f"{pad}        break;")
                        processed.add(tgt)
                lines.append(f"{pad}}}")
                processed.add(b.start_addr)
                i += 1
                continue

            # Case: If-Else Structuring
            if b.jump_type == 'cond' and len(b.successors) == 2:
                taken = b.successors[0]
                fall = b.successors[1]

                # Check if taken or fall is canary fail trap
                if taken.jump_type == 'canary_fail':
                    # Ignore condition and fallthrough
                    for s in b.statements:
                        lines.append(f"{pad}{clean_statement_text(s)}")
                    processed.add(b.start_addr)
                    processed.add(taken.start_addr)
                    i = blocks.index(fall) if fall in blocks else i + 1
                    continue
                if fall.jump_type == 'canary_fail':
                    for s in b.statements:
                        lines.append(f"{pad}{clean_statement_text(s)}")
                    processed.add(b.start_addr)
                    processed.add(fall.start_addr)
                    i = blocks.index(taken) if taken in blocks else i + 1
                    continue

                for s in b.statements:
                    lines.append(f"{pad}{clean_statement_text(s)}")

                r_taken = ASTStructurer.find_reachable(taken)
                r_fall = ASTStructurer.find_reachable(fall)
                common = r_taken.intersection(r_fall)

                merge_block = block_map.get(min(common)) if common else None

                # Pattern A: If-Then-Else converging at common merge block
                if merge_block and merge_block != taken and merge_block != fall:
                    then_blocks = [block_map[a] for a in sorted(list(ASTStructurer.find_reachable(taken, stop_at=merge_block)))]
                    else_blocks = [block_map[a] for a in sorted(list(ASTStructurer.find_reachable(fall, stop_at=merge_block)))]

                    lines.append(f"{pad}if ({b.condition}) {{")
                    for tb in then_blocks:
                        for s in tb.statements:
                            lines.append(f"{pad}    {clean_statement_text(s)}")
                        processed.add(tb.start_addr)
                    if any(eb.statements for eb in else_blocks):
                        lines.append(f"{pad}}} else {{")
                        for eb in else_blocks:
                            for s in eb.statements:
                                lines.append(f"{pad}    {clean_statement_text(s)}")
                            processed.add(eb.start_addr)
                    lines.append(f"{pad}}}")

                    processed.add(b.start_addr)
                    i = blocks.index(merge_block) if merge_block in blocks else i + 1
                    continue

                # Pattern B: If-Then (fall is merge)
                if merge_block == fall:
                    then_blocks = [block_map[a] for a in sorted(list(ASTStructurer.find_reachable(taken, stop_at=merge_block)))]
                    lines.append(f"{pad}if ({b.condition}) {{")
                    for tb in then_blocks:
                        for s in tb.statements:
                            lines.append(f"{pad}    {clean_statement_text(s)}")
                        processed.add(tb.start_addr)
                    lines.append(f"{pad}}}")
                    processed.add(b.start_addr)
                    i = blocks.index(fall)
                    continue

                # Pattern C: If-Else (taken is merge)
                if merge_block == taken:
                    else_blocks = [block_map[a] for a in sorted(list(ASTStructurer.find_reachable(fall, stop_at=merge_block)))]
                    lines.append(f"{pad}if ({invert_condition(b.condition)}) {{")
                    for eb in else_blocks:
                        for s in eb.statements:
                            lines.append(f"{pad}    {clean_statement_text(s)}")
                        processed.add(eb.start_addr)
                    lines.append(f"{pad}}}")
                    processed.add(b.start_addr)
                    i = blocks.index(taken)
                    continue

                # Fallback conditional branch
                nxt = blocks[i + 1] if i + 1 < len(blocks) else None
                if taken != nxt:
                    lines.append(f"{pad}if ({b.condition}) goto L_{hex(taken.start_addr)};")
                else:
                    lines.append(f"{pad}if ({invert_condition(b.condition)}) goto L_{hex(fall.start_addr)};")
                processed.add(b.start_addr)
                i += 1
                continue

            # Case: Standard statements
            for s in b.statements:
                lines.append(f"{pad}{clean_statement_text(s)}")

            nxt = blocks[i + 1] if i + 1 < len(blocks) else None
            if b.jump_type == 'jmp' and b.successors:
                tgt = b.successors[0]
                if tgt != nxt:
                    lines.append(f"{pad}goto L_{hex(tgt.start_addr)};")

            processed.add(b.start_addr)
            i += 1

        lines.append("}\n")
        return "\n".join(lines).strip()


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy for section data to detect packed/encrypted code."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


class DeepAnalysisEngine:
    """
    Multi-pass inter-procedural binary analyzer:
    1. Binary security mitigations (NX, PIE, Canaries, RELRO) & Shannon section entropy.
    2. Inter-procedural Call Graph & Cross-References (XREFs: callers, callees, strings, globals).
    3. Cryptographic primitive & constant identification (TEA, MD5, SHA, CRC32, AES, RC4, Base64).
    4. Security vulnerability & anti-analysis auditing (format strings, buffer overflows, ptrace, rdtsc).
    5. Enhanced C decompilation with embedded threat intel & signature headers.
    """
    CRYPTO_CONSTANTS = {
        0x9e3779b9: ("TEA / XTEA Key Schedule Delta", "0x9e3779b9 (Golden Ratio constant)"),
        0x61c88647: ("TEA / XTEA Reverse Delta", "0x61c88647 (0x100000000 - 0x9e3779b9)"),
        0x67452301: ("MD5 / SHA-1 Initial State A", "0x67452301"),
        0xefcdab89: ("MD5 / SHA-1 Initial State B", "0xefcdab89"),
        0x98badcfe: ("MD5 / SHA-1 Initial State C", "0x98badcfe"),
        0x10325476: ("MD5 / SHA-1 Initial State D", "0x10325476"),
        0x6a09e667: ("SHA-256 Initial Hash H0", "0x6a09e667"),
        0xbb67ae85: ("SHA-256 Initial Hash H1", "0xbb67ae85"),
        0x3c6ef372: ("SHA-256 Initial Hash H2", "0x3c6ef372"),
        0xa54ff53a: ("SHA-256 Initial Hash H3", "0xa54ff53a"),
        0xedb88320: ("CRC32 Reversed Polynomial (IEEE 802.3)", "0xedb88320"),
        0x04c11db7: ("CRC32 Forward Polynomial", "0x04c11db7"),
        0x82f63b78: ("CRC32C Polynomial (Castagnoli)", "0x82f63b78"),
        0x13579bdf: ("LFSR / PRNG Seed", "0x13579bdf"),
        0xf5a4ada5: ("Linear Feedback / Custom Cipher Constant", "0xf5a4ada5"),
    }

    @staticmethod
    def audit_mitigations(ctx: BinaryContext) -> Dict[str, Any]:
        mitigations = {
            'format': 'Unknown',
            'arch': 'Unknown',
            'pie': False,
            'nx': False,
            'canary': False,
            'relro': 'None',
            'stripped': True,
            'high_entropy_sections': []
        }

        if isinstance(ctx.binary, lief.ELF.Binary):
            is_64 = '64' in str(ctx.binary.header.identity_class)
            mitigations['format'] = f"ELF {64 if is_64 else 32}-bit"
            mitigations['arch'] = str(ctx.binary.header.machine_type).replace('ARCH.', '')
            mitigations['pie'] = ctx.binary.is_pie
            mitigations['stripped'] = not ctx.binary.has_section('.symtab')

            for seg in ctx.binary.segments:
                if 'GNU_STACK' in str(seg.type):
                    mitigations['nx'] = not seg.has(lief.ELF.Segment.FLAGS.X)

            has_relro_seg = any('GNU_RELRO' in str(s.type) for s in ctx.binary.segments)
            bind_now = any('BIND_NOW' in str(d.tag) for d in ctx.binary.dynamic_entries)
            if has_relro_seg and bind_now:
                mitigations['relro'] = 'Full RELRO'
            elif has_relro_seg:
                mitigations['relro'] = 'Partial RELRO'
            else:
                mitigations['relro'] = 'No RELRO'

        elif isinstance(ctx.binary, lief.PE.Binary):
            is_64 = ctx.binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
            mitigations['format'] = f"PE Windows {64 if is_64 else 32}-bit"
            mitigations['arch'] = str(ctx.binary.header.machine).replace('MACHINE_TYPES.', '')
            has_opt = hasattr(ctx.binary, 'optional_header')
            mitigations['nx'] = ctx.binary.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT) if has_opt else False
            mitigations['pie'] = ctx.binary.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE) if has_opt else False
            mitigations['relro'] = 'N/A (Windows PE)'
            mitigations['stripped'] = not bool(ctx.binary.symbols)

        mitigations['canary'] = any('__stack_chk_fail' in name or '__security_check_cookie' in name for name in ctx.symbol_map.values())

        for s in ctx.binary.sections:
            if s.size > 0:
                ent = calculate_entropy(bytes(s.content))
                if ent >= 6.8:
                    mitigations['high_entropy_sections'].append((s.name, s.size, ent))

        return mitigations

    CRT_IGNORES = {
        '__abi_tag', '__dso_handle', '__TMC_END__', '__data_start', '_edata',
        '__bss_start', '_end', 'completed.0', 'completed.1', 'call_weak_fn',
        'frame_dummy', '_IO_stdin_used', '_DYNAMIC', '_GLOBAL_OFFSET_TABLE_',
        '__frame_dummy_init_array_entry', '__do_global_dtors_aux_fini_array_entry',
        '__init_array_start', '__init_array_end', '__fini_array_start', '__fini_array_end',
        'data_start', '_fp_hw', 'deregister_tm_clones', 'register_tm_clones',
        '_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
        '__native_startup_lock', '__native_startup_state', '__dyn_tls_init_callback',
        '__native_dllmain_reason', '__ImageBase', '_fmode', '_commode', 'has_cctor',
        'managedapp', '__p__environ', '__mingw_oldexcpt_handler', '__mingw_app_type',
        '__mingw_initltsdrot_force', '__mingw_initltsdyn_force', '__mingw_initltssuo_force',
        '_MINGW_INSTALL_DEBUG_MATHERR', 'mingw_app_type'
    }

    @staticmethod
    def analyze_ctf_logic(ctx: BinaryContext,
                          functions: List[Tuple[int, int, str]],
                          func_blocks_map: Dict[int, List[ILBlock]],
                          xrefs: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deeply analyzes binary logic and data to identify CTF flags, win paths, and validation algorithms."""
        findings: List[Dict[str, Any]] = []

        # 1. Scan binary sections for hardcoded flags and base64 patterns
        flag_regex = re.compile(rb'([a-zA-Z0-9_\-\.]{2,20}\{[A-Za-z0-9_\-\.+=!@#$%^&*?~]{4,100}\})')
        for sec in ctx.binary.sections:
            if sec.size == 0:
                continue
            data = bytes(sec.content)
            for m in flag_regex.finditer(data):
                cand = m.group(1).decode('latin1', errors='replace')
                findings.append({
                    'category': 'Hardcoded Flag Pattern',
                    'target': cand,
                    'location': f"{sec.name} @ {hex(sec.virtual_address + m.start())}",
                    'confidence': 'CRITICAL',
                    'details': f"Exact flag pattern match in binary section {sec.name}"
                })

            if any(k in sec.name for k in ['rodata', 'rdata', '.data', 'text']) and not sec.name.startswith(('/', '.debug', '.idata')):
                for m_b64 in re.finditer(rb'[A-Za-z0-9+/]{16,}={0,2}', data):
                    raw_b64 = m_b64.group(0)
                    try:
                        decoded = base64.b64decode(raw_b64)
                        if all(32 <= b <= 126 or b in (9, 10, 13) for b in decoded) and any(k in decoded.lower() for k in [b'flag', b'ctf', b'{', b'pass', b'secret', b'token', b'key', b'auth', b'admin']):
                            dec_str = decoded.decode('latin1', errors='replace')
                            findings.append({
                                'category': 'Base64 Encoded Flag / Secret',
                                'target': dec_str,
                                'location': f"{sec.name} @ {hex(sec.virtual_address + m_b64.start())}",
                                'confidence': 'HIGH',
                                'details': f"Decoded from Base64 string '{raw_b64.decode('latin1')}'"
                            })
                    except Exception:
                        pass

        # 2. Reconstruct stack-strings (immediate character/string assignments on stack)
        for s, e, name in functions:
            blocks = func_blocks_map.get(s, [])
            imm_strs = []
            for b in blocks:
                for stmt in b.statements:
                    m_imm = re.search(r'=\s*("([^"\\]|\\.)*")', stmt)
                    if m_imm:
                        imm_val = m_imm.group(1).strip('"')
                        if len(imm_val) >= 2:
                            imm_strs.append(imm_val)
            if any('ctf' in x.lower() or 'flag' in x.lower() or '{' in x for x in imm_strs):
                full_cand = "".join(imm_strs)
                findings.append({
                    'category': 'Stack-String Flag',
                    'target': full_cand,
                    'location': f"{name} @ {hex(s)}",
                    'confidence': 'CRITICAL',
                    'details': f"Reconstructed from immediate stack writes: {' + '.join([repr(x) for x in imm_strs[:6]])}"
                })

        # 3. Detect uncalled Win / Flag issuer functions
        for s, e, name in functions:
            blocks = func_blocks_map.get(s, [])
            all_stmts = [clean_statement_text(st) for b in blocks for st in b.statements]
            joined_code = "\n".join(all_stmts)

            m_file = re.search(r'(?:fopen|open|read|fread)\s*\(\s*(?:&?"([^"]*(?:flag|\.txt)[^"]*)")', joined_code, re.IGNORECASE)
            opens_flag = bool(m_file)
            prints_flag = any(k in joined_code.lower() for k in [
                'clearance badge issued', 'access granted', 'royal inscription',
                'here is your flag', 'flag:', 'congratulations', 'welcome, cadet'
            ])
            executes_shell = any(k in joined_code for k in ['/bin/sh', '/bin/bash', 'system(', 'execve('])
            is_backdoor_name = any(k in name.lower() for k in ['backdoor', 'shell', 'flag', 'secret', 'admin']) or (name.lower() in ('win', 'give_flag', 'print_flag', 'get_flag', 'cat_flag') or (name.lower().startswith('win_') and not name.lower().startswith(('winmain', 'win_main'))))
            has_root_callers = len(xrefs.get(s, {}).get('callers', [])) == 0

            if opens_flag or (prints_flag and name != 'main') or (executes_shell and name != 'main') or (is_backdoor_name and name != 'main'):
                role = "Uncalled Win / Backdoor Routine" if (has_root_callers and name != '_start') else "Win / Flag / Shell Issuer Routine"
                evidence = []
                if opens_flag:
                    evidence.append(f"Opens flag file '{m_file.group(1)}'")
                if executes_shell:
                    evidence.append("Spawns interactive shell / executes command")
                if prints_flag:
                    evidence.append("Prints victory / clearance / access granted output")
                if is_backdoor_name:
                    evidence.append(f"Function identifier indicates backdoor/win target ('{name}')")
                if has_root_callers and name != '_start':
                    evidence.append("Uncalled from main / root (potential ret2win candidate)")

                for st in all_stmts:
                    m_auth = re.search(r'==\s*(0x[0-9a-fA-F]{4,16}|-?0x[0-9a-fA-F]+|\d{4,})', st)
                    if m_auth:
                        evidence.append(f"Guarded by check: '{st.strip()}'")
                        break

                conf = 'CRITICAL' if (opens_flag or executes_shell or (is_backdoor_name and has_root_callers)) else 'HIGH'
                findings.append({
                    'category': role,
                    'target': name,
                    'location': hex(s),
                    'confidence': conf,
                    'details': "; ".join(evidence)
                })

        # 4. Key validation & verification algorithms
        for s, e, name in functions:
            blocks = func_blocks_map.get(s, [])
            all_stmts = [clean_statement_text(st) for b in blocks for st in b.statements]
            joined_code = "\n".join(all_stmts)

            evidence = []
            score = 0

            if re.search(r'\b(fgets|read|__isoc99_scanf|scanf|fread|cin|getline|recv)\b', joined_code):
                evidence.append("Receives input from stdin / stream")
                score += 20

            m_len = re.search(r'(?:strlen|size|length)\s*\(?[^)]*\)?\s*(?:==|!=)\s*(0x[0-9a-fA-F]+|\d+)', joined_code)
            if m_len:
                length_val = m_len.group(1)
                try:
                    dec_len = int(length_val, 16) if length_val.startswith('0x') else int(length_val)
                    evidence.append(f"Length constraint: {dec_len} chars ({length_val})")
                    score += 30
                except ValueError:
                    pass

            cmps = re.findall(r'\b(strcmp|strncmp|memcmp|bcmp|strcasecmp|memmem)\s*\(([^)]+)\)', joined_code)
            if cmps:
                for c_fn, c_args in cmps[:2]:
                    evidence.append(f"Validation comparison via {c_fn}({c_args})")
                    score += 35

            xor_ops = 0
            loop_count = 0
            for b in blocks:
                if b.jump_type in ('loop', 'backedge') or any(suc.start_addr <= b.start_addr for suc in b.successors):
                    loop_count += 1
                for ins in b.instructions:
                    if ins.mnemonic == 'xor' and len(ins.operands) == 2:
                        op0, op1 = ins.operands
                        if not (op0.type == 1 and op1.type == 1 and op0.reg == op1.reg):
                            xor_ops += 1
            if xor_ops > 0:
                if loop_count > 0:
                    evidence.append(f"Cipher/Deobfuscation loop ({xor_ops} non-zeroing XOR ops in {loop_count} loops)")
                    score += 40
                else:
                    evidence.append(f"XOR transformation ({xor_ops} non-zeroing XOR ops)")
                    score += 20

            if '<<' in joined_code or '>>' in joined_code:
                if any(b in joined_code for b in ['(1 <<', 'dl <<', 'rax <<', 'rcx <<']):
                    evidence.append("Bitwise permutation / shifting transform")
                    score += 20

            has_win = any(w in joined_code.lower() for w in ['valid', 'correct', 'access granted', 'congratulations'])
            has_fail = any(f in joined_code.lower() for f in ['invalid', 'wrong', 'access denied', 'failure', 'fail'])
            if has_win and has_fail:
                evidence.append("Dual branching to 'Valid/Correct' vs 'Invalid/Wrong'")
                score += 30
            elif has_win:
                evidence.append("Branches to success / valid state")
                score += 15

            for callee_info in xrefs.get(s, {}).get('callees', []):
                c_name = callee_info[0]
                if any(k in c_name.lower() for k in ['check', 'valid', 'auth', 'verify']):
                    evidence.append(f"Dispatches input to validation routine '{c_name}'")
                    score += 25

            if score >= 35:
                conf = "CRITICAL" if score >= 60 else "HIGH"
                findings.append({
                    'category': 'Key / Flag Validator',
                    'target': name,
                    'location': hex(s),
                    'confidence': conf,
                    'details': "; ".join(evidence)
                })

        # 5. Magic authorization & check constants
        for s, e, name in functions:
            blocks = func_blocks_map.get(s, [])
            for b in blocks:
                for ins in b.instructions:
                    if ins.mnemonic in ('mov', 'movabs', 'cmp') and len(ins.operands) == 2:
                        if ins.operands[1].type == 2:
                            val = ins.operands[1].imm & 0xFFFFFFFFFFFFFFFF
                            if val in (0x1337c0decafebeef, 0x1337c0debaadf00d, 0xdeadbeefcafebabe, 0x13371337, 0x617b2375f81ea7e1):
                                findings.append({
                                    'category': 'Magic Constant',
                                    'target': hex(val),
                                    'location': f"{name} @ {hex(ins.address)}",
                                    'confidence': 'HIGH',
                                    'details': f"Magic comparison / check constant: {hex(val)}"
                                })

        return findings

    @staticmethod
    def analyze_user_globals(ctx: BinaryContext,
                             functions: List[Tuple[int, int, str]],
                             func_blocks_map: Dict[int, List[ILBlock]]) -> List[Dict[str, Any]]:
        """Extracts and profiles all user-defined global variables in data, bss, and rodata."""
        mem_refs: Dict[int, Dict[str, Any]] = {}
        for s, e, name in functions:
            for b in func_blocks_map.get(s, []):
                for ins in b.instructions:
                    for op in ins.operands:
                        if op.type == 3: # MEM
                            base = ctx.md.reg_name(op.mem.base)
                            disp = op.mem.disp
                            target = (ins.address + ins.size + disp) if base == 'rip' else (disp if base in ('', None) and disp > 0 else None)
                            if target:
                                for sname, sec in ctx.sections.items():
                                    if sec['addr'] <= target < sec['addr'] + sec['size'] and any(d in sname for d in ['data', 'bss', 'rdata', 'rodata']) and not sname.startswith(('.idata', '__idata')):
                                        if target not in mem_refs:
                                            mem_refs[target] = {'funcs': set(), 'is_read': False, 'is_write': False, 'sec': sname, 'size': op.size}
                                        mem_refs[target]['funcs'].add(name)
                                        if ins.mnemonic in ('mov', 'movzx', 'movsx') and len(ins.operands) == 2 and ins.operands[0] == op:
                                            mem_refs[target]['is_write'] = True
                                        else:
                                            mem_refs[target]['is_read'] = True

        globals_list: List[Dict[str, Any]] = []
        seen_addrs: Set[int] = set()

        if isinstance(ctx.binary, lief.PE.Binary):
            secs = list(ctx.binary.sections)
            for sym in ctx.binary.symbols:
                if not sym.name or sym.name.startswith(('.', '/')) or sym.is_function:
                    continue
                if 1 <= sym.section_idx <= len(secs):
                    sec = secs[sym.section_idx - 1]
                    sec_name = sec.name
                    if any(d in sec_name for d in ['data', 'bss', 'rdata', 'rodata']) and not sec_name.startswith(('/', '.debug', '.idata')):
                        clean_name = sym.name.split('@')[0]
                        if clean_name in DeepAnalysisEngine.CRT_IGNORES or clean_name.startswith(('__', '_ITM', '_IO_')) or '.refptr.' in clean_name:
                            continue
                        addr = sec.virtual_address + sym.value
                        if addr in seen_addrs:
                            continue
                        seen_addrs.add(addr)
                        access = mem_refs.get(addr, {'funcs': set(), 'is_read': False, 'is_write': False, 'size': sym.size})
                        globals_list.append({
                            'name': clean_name,
                            'addr': addr,
                            'section': sec_name,
                            'size': sym.size if sym.size > 0 else access.get('size', 8),
                            'access': access,
                            'has_symbol': True
                        })
        else:
            for sym in ctx.binary.symbols:
                if sym.value > 0 and not sym.is_function:
                    sec_name = sym.section.name if hasattr(sym, 'section') and sym.section else ''
                    if any(d in sec_name for d in ['data', 'bss', 'rodata']):
                        clean_name = sym.name.split('@')[0]
                        if clean_name in DeepAnalysisEngine.CRT_IGNORES or clean_name.startswith(('__', '_ITM', '_IO_')):
                            continue
                        if sym.value in seen_addrs:
                            continue
                        seen_addrs.add(sym.value)
                        access = mem_refs.get(sym.value, {'funcs': set(), 'is_read': False, 'is_write': False, 'size': sym.size})
                        globals_list.append({
                            'name': clean_name,
                            'addr': sym.value,
                            'section': sec_name,
                            'size': sym.size if sym.size > 0 else access.get('size', 8),
                            'access': access,
                            'has_symbol': True
                        })

        # Add referenced unnamed memory locations in .data or .bss (for stripped binaries)
        for addr, rinfo in mem_refs.items():
            if addr not in seen_addrs:
                sec_name = rinfo['sec']
                if 'rodata' in sec_name or 'rdata' in sec_name:
                    continue
                # Skip completed.0 / dtor auxiliary flags
                funcs = rinfo.get('funcs', set())
                if funcs == {'__do_global_dtors_aux'} or funcs == {'__cxa_finalize'}:
                    continue
                seen_addrs.add(addr)
                sec_clean = sec_name.replace('.', '')
                synth_name = f"g_{sec_clean}_{hex(addr)}"
                globals_list.append({
                    'name': synth_name,
                    'addr': addr,
                    'section': sec_name,
                    'size': rinfo['size'],
                    'access': rinfo,
                    'has_symbol': False
                })

        # Initial values and previews
        for g in globals_list:
            addr = g['addr']
            sec = g['section']
            val_preview = "0 (Uninitialized BSS)"
            if 'bss' not in sec:
                for sname, sdata in ctx.sections.items():
                    if sdata['addr'] <= addr < sdata['addr'] + sdata['size']:
                        offset = addr - sdata['addr']
                        content = sdata['data'][offset:offset + max(g['size'], 16)]
                        null_pos = content.find(b'\x00')
                        if null_pos > 0 and all(32 <= b <= 126 or b in (9, 10, 13) for b in content[:null_pos]):
                            val_preview = f'"{content[:null_pos].decode("latin1")}"'
                        elif len(content) >= 8:
                            qword = struct.unpack('<Q', content[:8])[0]
                            deref_str = ctx.read_string(qword)
                            if deref_str:
                                val_preview = f"{hex(qword)} (-> {deref_str})"
                            else:
                                val_preview = f"{hex(qword)} ({qword})"
                        elif len(content) >= 4:
                            dword = struct.unpack('<I', content[:4])[0]
                            deref_str = ctx.read_string(dword)
                            if deref_str:
                                val_preview = f"{hex(dword)} (-> {deref_str})"
                            else:
                                val_preview = f"{hex(dword)} ({dword})"
                        else:
                            val_preview = " ".join(f"{b:02x}" for b in content[:8])
                        break
            g['preview'] = val_preview

            # CTF Context classification
            g_name = g['name'].lower()
            if any(k in g_name for k in ['size', 'chunk', 'table', 'list', 'entry', 'ptr']):
                g['ctf_role'] = 'Heap / Buffer Table'
            elif any(k in g_name for k in ['state', 'flag', 'auth', 'pass', 'key', 'valid', 'empire']):
                g['ctf_role'] = 'State / Verification Variable'
            elif any(k in g_name for k in ['stdout', 'stdin', 'stderr']):
                g['ctf_role'] = 'Standard I/O Stream'
            elif 'rodata' in sec:
                g['ctf_role'] = 'Constant / Expected Buffer'
            else:
                g['ctf_role'] = 'User Global Variable'

        return sorted(globals_list, key=lambda x: x['addr'])

    @staticmethod
    def analyze(ctx: BinaryContext, functions: List[Tuple[int, int, str]]) -> Dict[str, Any]:
        mitigations = DeepAnalysisEngine.audit_mitigations(ctx)
        func_lookup = {s: name for s, e, name in functions}
        func_blocks_map: Dict[int, List[ILBlock]] = {}
        xrefs: Dict[int, Dict[str, Any]] = {
            s: {
                'name': name,
                'start': s,
                'end': e,
                'callers': set(),
                'callees': set(),
                'strings': set(),
                'globals': set(),
                'complexity': 1,
                'is_leaf': True
            } for s, e, name in functions
        }

        for s, e, name in functions:
            blocks = InstructionLifter.lift(ctx, s, e)
            if not blocks:
                continue
            func_blocks_map[s] = blocks

            edges = sum(len(b.successors) for b in blocks)
            nodes = len(blocks)
            xrefs[s]['complexity'] = max(1, edges - nodes + 2)

            for b in blocks:
                for ins in b.instructions:
                    m = ins.mnemonic
                    if m in ('call', 'bl'):
                        xrefs[s]['is_leaf'] = False
                        try:
                            tgt = int(ins.op_str.split(',')[0], 16)
                            callee_name = ctx.symbol_map.get(tgt, func_lookup.get(tgt, f"func_{hex(tgt)}"))
                            xrefs[s]['callees'].add((callee_name, hex(tgt), hex(ins.address)))
                            if tgt in xrefs:
                                xrefs[tgt]['callers'].add((name, hex(s), hex(ins.address)))
                        except ValueError:
                            tgt_str = ins.op_str.split(',')[0]
                            xrefs[s]['callees'].add((tgt_str, "external", hex(ins.address)))

                    for op in ins.operands:
                        if op.type == 3: # MEM
                            target = (ins.address + ins.size + op.mem.disp) if ctx.md.reg_name(op.mem.base) == 'rip' else op.mem.disp
                            s_lit = ctx.read_string(target)
                            if s_lit:
                                xrefs[s]['strings'].add(s_lit)
                            elif target in ctx.symbol_map:
                                xrefs[s]['globals'].add(ctx.symbol_map[target])
                            else:
                                for sname, sec in ctx.sections.items():
                                    if sec['addr'] <= target < sec['addr'] + sec['size'] and any(d in sname for d in ['data', 'bss']):
                                        sec_clean = sname.replace('.', '')
                                        xrefs[s]['globals'].add(f"g_{sec_clean}_{hex(target)}")

        detected_crypto = []
        for s, e, name in functions:
            blocks = func_blocks_map.get(s, [])
            for b in blocks:
                for ins in b.instructions:
                    for op in ins.operands:
                        if op.type == 2: # IMM
                            val = op.imm & 0xFFFFFFFF
                            if val in DeepAnalysisEngine.CRYPTO_CONSTANTS:
                                c_name, c_desc = DeepAnalysisEngine.CRYPTO_CONSTANTS[val]
                                detected_crypto.append({
                                    'function': name,
                                    'func_addr': hex(s),
                                    'address': hex(ins.address),
                                    'primitive': c_name,
                                    'details': c_desc,
                                    'constant': hex(val)
                                })

        for sec in ctx.binary.sections:
            if 'rodata' in sec.name or 'data' in sec.name:
                content = bytes(sec.content)
                if b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" in content:
                    detected_crypto.append({
                        'function': 'Global Data',
                        'func_addr': hex(sec.virtual_address),
                        'address': hex(sec.virtual_address),
                        'primitive': 'Base64 Alphabet Table',
                        'details': 'Standard Base64 character table found',
                        'constant': 'RFC 4648'
                    })

        vulnerabilities = []
        for s, e, name in functions:
            blocks = func_blocks_map.get(s, [])
            for b in blocks:
                for stmt in b.statements:
                    cleaned = clean_statement_text(stmt)
                    m_pf = re.match(r'^(printf|dprintf|vprintf)\s*\(\s*([^,]+)\)', cleaned)
                    if m_pf:
                        arg0 = m_pf.group(2).strip()
                        if not arg0.startswith('"'):
                            vulnerabilities.append({
                                'severity': 'HIGH',
                                'type': 'Format String Vulnerability (CWE-134)',
                                'function': name,
                                'address': hex(b.start_addr),
                                'code': cleaned,
                                'recommendation': 'Pass explicit format string: printf("%s", input)'
                            })
                    if re.search(r'\bgets\s*\(', cleaned):
                        vulnerabilities.append({
                            'severity': 'CRITICAL',
                            'type': 'Buffer Overflow via gets() (CWE-120)',
                            'function': name,
                            'address': hex(b.start_addr),
                            'code': cleaned,
                            'recommendation': 'Replace with fgets(buf, sizeof(buf), stdin)'
                        })
                    if re.search(r'\b(strcpy|strcat|sprintf)\s*\(', cleaned):
                        vulnerabilities.append({
                            'severity': 'MEDIUM',
                            'type': 'Unbounded String Copy (CWE-120)',
                            'function': name,
                            'address': hex(b.start_addr),
                            'code': cleaned,
                            'recommendation': 'Use size-bounded alternatives (strncpy, snprintf)'
                        })
                    if 'ptrace' in cleaned:
                        vulnerabilities.append({
                            'severity': 'INFO',
                            'type': 'Anti-Debugging Check (PTRACE)',
                            'function': name,
                            'address': hex(b.start_addr),
                            'code': cleaned,
                            'recommendation': 'Patch ptrace call to NOP (0x90) to bypass in debugger'
                        })

        ctf_report = DeepAnalysisEngine.analyze_ctf_logic(ctx, functions, func_blocks_map, xrefs)
        globals_report = DeepAnalysisEngine.analyze_user_globals(ctx, functions, func_blocks_map)

        return {
            'mitigations': mitigations,
            'xrefs': xrefs,
            'crypto': detected_crypto,
            'vulnerabilities': vulnerabilities,
            'ctf': ctf_report,
            'globals': globals_report
        }

    @staticmethod
    def render_dashboard(report: Dict[str, Any], console: Optional[Console], raw_output: bool = False):
        mits = report['mitigations']
        cryptos = report['crypto']
        vulns = report['vulnerabilities']
        xrefs = report['xrefs']
        ctf_findings = report.get('ctf', [])
        user_globals = report.get('globals', [])

        if console and not raw_output:
            mit_table = Table(box=box.ROUNDED, title="[bold cyan]Binary Security Mitigations[/]", expand=True)
            mit_table.add_column("Security Feature", style="bold white", width=24)
            mit_table.add_column("Status / Setting", width=20)
            mit_table.add_column("Details", style="dim")

            nx_style = "bold green" if mits['nx'] else "bold red"
            pie_style = "bold green" if mits['pie'] else "bold yellow"
            can_style = "bold green" if mits['canary'] else "bold yellow"
            rel_style = "bold green" if 'Full' in mits['relro'] else ("bold yellow" if 'Partial' in mits['relro'] else "bold red")
            str_style = "bold cyan" if mits['stripped'] else "bold magenta"

            mit_table.add_row("Format & Architecture", f"{mits['format']} / {mits['arch']}", "Target instruction set & file container")
            mit_table.add_row("NX / DEP (No-Execute)", Text("Enabled" if mits['nx'] else "Disabled", style=nx_style), "Executable stack memory protection")
            mit_table.add_row("PIE / ASLR", Text("Enabled" if mits['pie'] else "Disabled", style=pie_style), "Position Independent Executable")
            mit_table.add_row("Stack Canary", Text("Present" if mits['canary'] else "Not Detected", style=can_style), "fs:[0x28] / __stack_chk_fail guard")
            mit_table.add_row("RELRO", Text(mits['relro'], style=rel_style), "GOT overwrite protection")
            mit_table.add_row("Symbols", Text("Stripped" if mits['stripped'] else "Symbols Present", style=str_style), "Function names & debug symbol presence")
            console.print(mit_table)

            if ctf_findings:
                ctf_table = Table(box=box.ROUNDED, title="[bold red]CTF Logic & Flag Analysis Findings[/]", expand=True)
                ctf_table.add_column("Category", style="bold yellow", width=26)
                ctf_table.add_column("Target / Function", style="bold white", width=20)
                ctf_table.add_column("Confidence", style="bold magenta", width=12)
                ctf_table.add_column("Evidence & Logic Details", style="bright_white")

                for f in ctf_findings:
                    conf = f['confidence']
                    conf_style = "bold red" if conf == "CRITICAL" else ("bold yellow" if conf == "HIGH" else "bold cyan")
                    ctf_table.add_row(
                        f['category'],
                        f['target'],
                        Text(f"[{conf}]", style=conf_style),
                        f['details']
                    )
                console.print(ctf_table)

            if user_globals:
                global_table = Table(box=box.ROUNDED, title="[bold green]User-Defined Global Variables (.data / .bss / .rodata)[/]", expand=True)
                global_table.add_column("Variable Name", style="bold white", width=22)
                global_table.add_column("Address", style="dim cyan", width=12)
                global_table.add_column("Section", style="dim yellow", width=10)
                global_table.add_column("Size", style="dim white", width=8, justify="right")
                global_table.add_column("Initial Value / Preview", style="bright_white", width=28)
                global_table.add_column("Access", style="bold magenta", width=8, justify="center")
                global_table.add_column("Referenced In", style="dim green", width=24)
                global_table.add_column("CTF Role / Context", style="bold cyan")

                for g in user_globals:
                    acc = "RW" if (g['access']['is_read'] and g['access']['is_write']) else ("WRITE" if g['access']['is_write'] else "READ")
                    funcs_str = ", ".join(sorted(list(g['access']['funcs']))) or "Unreferenced"
                    global_table.add_row(
                        g['name'],
                        hex(g['addr']),
                        g['section'],
                        f"{g['size']}B",
                        g['preview'],
                        acc,
                        funcs_str,
                        g.get('ctf_role', 'Global Variable')
                    )
                console.print(global_table)

            if cryptos:
                crypto_table = Table(box=box.ROUNDED, title="[bold yellow]Cryptographic Primitives & Constants Detected[/]", expand=True)
                crypto_table.add_column("Primitive / Algorithm", style="bold yellow", width=30)
                crypto_table.add_column("Constant / Hash", style="bold cyan", width=18)
                crypto_table.add_column("Function", style="bright_white", width=18)
                crypto_table.add_column("Address", style="dim cyan", width=12)
                crypto_table.add_column("Details", style="dim")

                for c in cryptos:
                    crypto_table.add_row(c['primitive'], c['constant'], c['function'], c['address'], c['details'])
                console.print(crypto_table)

            if vulns:
                vuln_table = Table(box=box.ROUNDED, title="[bold red]Security Audit & Vulnerability Findings[/]", expand=True)
                vuln_table.add_column("Severity", width=12)
                vuln_table.add_column("Vulnerability Type", style="bold white", width=32)
                vuln_table.add_column("Function", style="bright_white", width=16)
                vuln_table.add_column("Location", style="dim cyan", width=12)
                vuln_table.add_column("Statement / Finding", style="dim red", width=30)
                vuln_table.add_column("Remediation", style="dim green")

                for v in vulns:
                    sev = v['severity']
                    sev_style = "bold red" if sev == "CRITICAL" else ("bold bright_red" if sev == "HIGH" else ("bold yellow" if sev == "MEDIUM" else "bold cyan"))
                    vuln_table.add_row(
                        Text(f"[{sev}]", style=sev_style),
                        v['type'],
                        v['function'],
                        v['address'],
                        escape(v['code']),
                        v['recommendation']
                    )
                console.print(vuln_table)

            metric_table = Table(box=box.ROUNDED, title="[bold blue]Function Metrics & Call Graph Summary[/]", expand=True)
            metric_table.add_column("Function", style="bold white", width=22)
            metric_table.add_column("Address Range", style="dim cyan", width=22)
            metric_table.add_column("Complexity (M)", style="bold yellow", width=14, justify="right")
            metric_table.add_column("Callers", style="dim green", width=10, justify="right")
            metric_table.add_column("Callees", style="dim magenta", width=10, justify="right")
            metric_table.add_column("Strings", style="dim cyan", width=10, justify="right")
            metric_table.add_column("Role / Profile", style="bold cyan")

            sorted_funcs = sorted(xrefs.values(), key=lambda x: x['complexity'], reverse=True)
            for f in sorted_funcs[:15]:
                role = "Main Entry" if f['name'] == 'main' else (
                    "Crypto / Algorithm" if any(c['function'] == f['name'] for c in cryptos) else (
                        "Complex Logic" if f['complexity'] >= 5 else (
                            "Leaf Helper" if f['is_leaf'] else "Standard Logic"
                        )
                    )
                )
                metric_table.add_row(
                    f['name'],
                    f"{hex(f['start'])} - {hex(f['end'])}",
                    str(f['complexity']),
                    str(len(f['callers'])),
                    str(len(f['callees'])),
                    str(len(f['strings'])),
                    role
                )
            console.print(metric_table)
        else:
            print("\n" + "="*80)
            print("  DEEP BINARY ANALYSIS REPORT")
            print("="*80)
            print(f"Format & Arch:  {mits['format']} / {mits['arch']}")
            print(f"Mitigations:    NX={'Enabled' if mits['nx'] else 'Disabled'} | PIE={'Enabled' if mits['pie'] else 'Disabled'} | Canary={'Yes' if mits['canary'] else 'No'} | RELRO={mits['relro']}")
            print(f"Symbols:        {'Stripped' if mits['stripped'] else 'Symbols Present'}")

            if ctf_findings:
                print("\nCTF Logic & Flag Analysis Findings:")
                for f in ctf_findings:
                    print(f"  * [{f['confidence']}] {f['category']} in {f['target']} @ {f.get('location', 'N/A')}: {f['details']}")

            if user_globals:
                print("\nUser-Defined Global Variables (.data / .bss / .rodata):")
                for g in user_globals:
                    acc = "RW" if (g['access']['is_read'] and g['access']['is_write']) else ("WRITE" if g['access']['is_write'] else "READ")
                    funcs_str = ", ".join(sorted(list(g['access']['funcs']))) or "Unreferenced"
                    print(f"  * {g['name']:<22} @ {hex(g['addr']):<10} [{g['section']}] (Size={g['size']}B, Access={acc}, Value={g['preview']}, Role={g.get('ctf_role', 'Global')}) Used in: {funcs_str}")

            if cryptos:
                print("\nCryptographic Primitives Detected:")
                for c in cryptos:
                    print(f"  * {c['primitive']} in {c['function']} @ {c['address']} ({c['details']})")

            if vulns:
                print("\nSecurity Audit Findings:")
                for v in vulns:
                    print(f"  * [{v['severity']}] {v['type']} in {v['function']} @ {v['address']}: {v['code']}")

            print("\nTop Functions by Cyclomatic Complexity:")
            sorted_funcs = sorted(xrefs.values(), key=lambda x: x['complexity'], reverse=True)
            for f in sorted_funcs[:8]:
                print(f"  * {f['name']:<18} @ {hex(f['start']):<10} (Complexity={f['complexity']}, Callers={len(f['callers'])}, Callees={len(f['callees'])})")
            print("="*80 + "\n")

    @staticmethod
    def generate_function_header(func_info: Tuple[int, int, str],
                                 xrefs: Dict[str, Any],
                                 cryptos: List[Dict[str, Any]],
                                 vulns: List[Dict[str, Any]],
                                 ctf_findings: Optional[List[Dict[str, Any]]] = None,
                                 user_globals: Optional[List[Dict[str, Any]]] = None) -> str:
        s, e, name = func_info
        lines = []
        lines.append("// ================================================================================")
        lines.append(f"// Function: {name} ({hex(s)} - {hex(e)})")
        lines.append(f"// Cyclomatic Complexity: {xrefs.get('complexity', 1)}")

        callers = [f"{c[0]} @ {c[2]}" for c in xrefs.get('callers', [])]
        if callers:
            lines.append(f"// Callers ({len(callers)}): {', '.join(callers[:6])}")
        else:
            lines.append("// Callers: None (Entry / Root)")

        callees = [f"{c[0]}" for c in xrefs.get('callees', [])]
        if callees:
            lines.append(f"// Callees ({len(callees)}): {', '.join(sorted(list(set(callees))))}")

        # Globals accessed
        fn_globals = set()
        user_vars_added = set()
        if user_globals:
            for g in user_globals:
                if name in g.get('access', {}).get('funcs', set()):
                    acc = "RW" if (g['access']['is_read'] and g['access']['is_write']) else ("WRITE" if g['access']['is_write'] else "READ")
                    fn_globals.add(f"{g['name']} ({acc})")
                    user_vars_added.add(g['name'])
        for raw_g in xrefs.get('globals', set()):
            if raw_g not in user_vars_added:
                fn_globals.add(raw_g)
        if fn_globals:
            lines.append(f"// Globals Accessed ({len(fn_globals)}): {', '.join(sorted(list(fn_globals)))}")

        if ctf_findings:
            f_ctf = [f for f in ctf_findings if f.get('target') == name or hex(s).lower() in f.get('location', '').lower()]
            for f in f_ctf:
                lines.append(f"// [!] CTF LOGIC: [{f['confidence']}] {f['category']} -> {f['details']}")

        f_cryptos = [c for c in cryptos if c['function'] == name]
        for c in f_cryptos:
            lines.append(f"// [!] CRYPTO IDENTIFIED: {c['primitive']} ({c['details']}) at {c['address']}")

        f_vulns = [v for v in vulns if v['function'] == name]
        for v in f_vulns:
            lines.append(f"// [!] SECURITY ALERT: [{v['severity']}] {v['type']} at {v['address']} -> {v['recommendation']}")

        lines.append("// ================================================================================")
        return "\n".join(lines)


def print_function_disassembly(blocks: List[ILBlock],
                               ctx: BinaryContext,
                               func_name: str,
                               func_addr: int,
                               raw_output: bool = False,
                               console: Optional[Console] = None):
    """Outputs modern, high-clarity block-by-block disassembly, lifted statements, and CFG edges."""
    if not blocks:
        return

    if console and not raw_output:
        header_text = Text()
        header_text.append("FUNCTION: ", style="bold magenta")
        header_text.append(f"{func_name} ", style="bold white")
        header_text.append(f"@ {hex(func_addr)}", style="bold cyan")
        header_text.append(f"  |  {len(blocks)} Basic Blocks", style="dim white")
        total_instrs = sum(len(b.instructions) for b in blocks)
        header_text.append(f"  |  {total_instrs} Instructions", style="dim white")
        console.print(Panel(header_text, border_style="bright_blue", box=box.ROUNDED))
    else:
        print(f"\n================================================================================")
        print(f"  FUNCTION: {func_name} @ {hex(func_addr)}  ({len(blocks)} Blocks, {sum(len(b.instructions) for b in blocks)} Instructions)")
        print(f"================================================================================")

    for b_idx, block in enumerate(blocks):
        inst_rows = []
        for instr in block.instructions:
            ann = ""
            m = instr.mnemonic
            op_str = instr.op_str

            if m in ('call', 'bl'):
                try:
                    tgt = int(op_str.split(',')[0], 16)
                    if tgt in ctx.symbol_map:
                        ann = f"-> {ctx.symbol_map[tgt]}()"
                except ValueError:
                    pass
            elif 'rip +' in op_str or 'rip -' in op_str:
                for op in instr.operands:
                    if op.type == CS_OP_MEM:
                        t = instr.address + instr.size + op.mem.disp
                        s = ctx.read_string(t)
                        if s:
                            ann = s
                        elif t in ctx.symbol_map:
                            ann = f"&{ctx.symbol_map[t]}"
            elif m.startswith('j') or m.startswith('b'):
                try:
                    tgt = int(op_str.split(',')[0], 16)
                    if tgt in ctx.symbol_map:
                        ann = f"-> {ctx.symbol_map[tgt]}"
                    else:
                        ann = f"-> Block @ {hex(tgt)}"
                except ValueError:
                    pass

            inst_rows.append((hex(instr.address), instr.mnemonic, instr.op_str, ann))

        succs_str = ", ".join([hex(s.start_addr) for s in block.successors]) or "None (Function Exit)"
        preds_str = ", ".join([hex(p.start_addr) for p in block.predecessors]) or "None (Function Entry)"
        jtype = block.jump_type or "fallthrough"

        if console and not raw_output:
            table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True, padding=(0, 1))
            table.add_column("Address", style="cyan dim", width=12, no_wrap=True)
            table.add_column("Mnemonic", style="bold yellow", width=10)
            table.add_column("Operands", style="bright_white", width=34)
            table.add_column("Annotation / Symbol", style="italic dim magenta")

            for addr_s, mnem, ops, ann in inst_rows:
                mnem_style = "bold yellow" if mnem in ('call', 'bl', 'jmp', 'ret', 'leave') or mnem.startswith('j') else (
                    "bold green" if mnem in ('add', 'sub', 'xor', 'and', 'or', 'shl', 'shr', 'imul', 'inc', 'dec') else (
                        "bold cyan" if mnem in ('mov', 'movzx', 'movsx', 'movsxd', 'lea') else (
                            "bold bright_red" if mnem in ('cmp', 'test') else "dim white"
                        )
                    )
                )
                table.add_row(addr_s, Text(mnem, style=mnem_style), escape(ops), escape(ann))

            block_elements = [table]

            if block.statements:
                c_section = Text()
                c_section.append("\n-- Lifted C Statements ------------------------------------------\n", style="bold cyan")
                for s in block.statements:
                    c_section.append(f"  {clean_statement_text(s)}\n", style="bold green")
                block_elements.append(c_section)

            cfg_section = Text()
            cfg_section.append("\n-- Control Flow Graph -------------------------------------------\n", style="bold blue")
            cfg_section.append("  Jump Type:    ", style="dim")
            cfg_section.append(f"{jtype}\n", style="bold yellow")

            if len(block.successors) == 2:
                cfg_section.append("  Successors:   ", style="dim")
                cfg_section.append(f"True/Taken -> {hex(block.successors[0].start_addr)}", style="bold green")
                cfg_section.append(f"  |  False/Fall -> {hex(block.successors[1].start_addr)}\n", style="bold red")
            elif len(block.successors) == 1:
                cfg_section.append("  Successor:    ", style="dim")
                cfg_section.append(f"-> {hex(block.successors[0].start_addr)}\n", style="bold green")
            else:
                cfg_section.append("  Successor:    ", style="dim")
                cfg_section.append("Return / Terminal\n", style="bold magenta")

            cfg_section.append("  Predecessors: ", style="dim")
            cfg_section.append(f"{preds_str}", style="dim cyan")
            block_elements.append(cfg_section)

            title_str = f"[bold white]Basic Block[/] [bold yellow]@{hex(block.start_addr)}[/] [dim]({len(block.instructions)} instrs)[/dim]"
            border = "green" if b_idx == 0 else ("magenta" if not block.successors else "bright_blue")
            console.print(Panel(Group(*block_elements), title=title_str, border_style=border, box=box.ROUNDED))

            if b_idx + 1 < len(blocks):
                console.print("       [dim blue]|[/]\n       [bold blue]v[/]")
        else:
            print(f"\n+-- Basic Block @ {hex(block.start_addr)} ({len(block.instructions)} instructions) -----------------------")
            for addr_s, mnem, ops, ann in inst_rows:
                ann_str = f"  ; {ann}" if ann else ""
                print(f"|  {addr_s:<10}  {mnem:<8} {ops:<30}{ann_str}")
            if block.statements:
                print(f"|-- Lifted C Logic -------------------------------------------------------------")
                for s in block.statements:
                    print(f"|    {clean_statement_text(s)}")
            print(f"|-- Control Flow ---------------------------------------------------------------")
            print(f"|    Jump Type:    {jtype}")
            print(f"|    Successors:   {succs_str}")
            print(f"|    Predecessors: {preds_str}")
            print(f"+-------------------------------------------------------------------------------")
            if b_idx + 1 < len(blocks):
                print(f"       |\n       v")


def decompile_binary(filename: str,
                     disasm_only: bool = False,
                     decompile_only: bool = True,
                     deep_analysis: bool = False,
                     target_func: Optional[str] = None,
                     output_file: Optional[str] = None,
                     raw_output: bool = False):
    """Main analysis driver."""
    print(f"Analyzing binary: {filename}")
    try:
        ctx = BinaryContext(filename)
    except Exception as e:
        print(f"[!] Error loading binary: {e}")
        return

    print(f"Loaded {len(ctx.symbol_map)} symbols and relocations.")

    functions = FunctionFinder.find_functions(ctx)
    print(f"Discovered {len(functions)} functions.")

    if target_func:
        target_clean = target_func.strip().lower()
        matched = []
        for start, end, name in functions:
            if name.lower() == target_clean or hex(start).lower() == target_clean or str(start) == target_clean:
                matched.append((start, end, name))
        if not matched:
            print(f"[!] Target function '{target_func}' not found in binary.")
            return
        functions = matched

    all_decompiled_code: List[str] = []
    dashboard_summary_text: Optional[str] = None
    console = Console() if RICH_AVAILABLE and not raw_output and sys.stdout.isatty() else None

    # MODE 1: Deep Inter-Procedural Analysis
    if deep_analysis:
        if console and not raw_output:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
                progress.add_task("[bold cyan]Running deep binary analysis & vulnerability audit...[/]", total=None)
                report = DeepAnalysisEngine.analyze(ctx, functions)
        else:
            report = DeepAnalysisEngine.analyze(ctx, functions)

        DeepAnalysisEngine.render_dashboard(report, console, raw_output=raw_output)

        if output_file:
            if RICH_AVAILABLE and not raw_output:
                buf = io.StringIO()
                file_console = Console(file=buf, width=120, no_color=True, highlight=False)
                file_console.print("=" * 120)
                file_console.print("  DEEP BINARY ANALYSIS REPORT")
                file_console.print("=" * 120)
                DeepAnalysisEngine.render_dashboard(report, file_console, raw_output=False)
                dashboard_summary_text = buf.getvalue().strip()
            else:
                old_stdout = sys.stdout
                sys.stdout = buf = io.StringIO()
                try:
                    DeepAnalysisEngine.render_dashboard(report, None, raw_output=True)
                finally:
                    sys.stdout = old_stdout
                dashboard_summary_text = buf.getvalue().strip()

        for start_addr, end_addr, func_name in functions:
            header = DeepAnalysisEngine.generate_function_header(
                (start_addr, end_addr, func_name),
                report['xrefs'].get(start_addr, {}),
                report['crypto'],
                report['vulnerabilities'],
                report.get('ctf', []),
                report.get('globals', [])
            )
            c_code = ASTStructurer.decompile(ctx, start_addr, end_addr).strip()
            full_fn = f"{header}\n{c_code}"
            all_decompiled_code.append(full_fn)

            if console and not raw_output:
                panel_header = f"[bold cyan]{func_name}[/] [dim]({hex(start_addr)} - {hex(end_addr)})[/dim]"
                console.print(Panel(Syntax(full_fn, "c", theme="monokai", line_numbers=False),
                                    title=panel_header, border_style="bright_blue", box=box.ROUNDED))
            else:
                print(full_fn + "\n")

    # MODE 2: Block-by-Block Disassembly View
    elif disasm_only:
        for start_addr, end_addr, func_name in functions:
            blocks = InstructionLifter.lift(ctx, start_addr, end_addr)
            if blocks:
                print_function_disassembly(blocks, ctx, func_name, start_addr, raw_output=raw_output, console=console)

    # MODE 3: High-Level C Decompilation (Default)
    else:
        for start_addr, end_addr, func_name in functions:
            c_code = ASTStructurer.decompile(ctx, start_addr, end_addr).strip()
            all_decompiled_code.append(c_code)

            if console and not raw_output:
                panel_header = f"[bold cyan]{func_name}[/] [dim]({hex(start_addr)} - {hex(end_addr)})[/dim]"
                console.print(Panel(Syntax(c_code, "c", theme="monokai", line_numbers=False),
                                    title=panel_header, border_style="bright_blue", box=box.ROUNDED))
            else:
                print(f"// ==================== {func_name} ({hex(start_addr)}) ====================")
                print(c_code + "\n")

    if output_file and (all_decompiled_code or dashboard_summary_text):
        try:
            out_dir = os.path.dirname(output_file)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"// Decompiled from {filename} by declaw\n\n")
                if dashboard_summary_text:
                    safe_summary = dashboard_summary_text.replace("*/", "* /")
                    f.write("/*\n")
                    f.write(safe_summary)
                    f.write("\n*/\n\n")
                f.write("#include <stdint.h>\n#include <stdbool.h>\n#include <string.h>\n#include <stdio.h>\n#include <stdlib.h>\n\n")
                for code in all_decompiled_code:
                    f.write(code + "\n\n")
            print(f"\nSuccessfully saved decompiled code to: {output_file}")
        except Exception as e:
            print(f"[!] Error writing to output file: {e}")

    print("\n★\t\tAnalysis complete.\t\tThis Decompiler is made with <3 by shiny_02\t\t★")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='declaw.py',
        description='declaw - Next-Generation C Binary Decompiler & Binary Analysis Engine',
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-dasm', '-ds', '--disasm', action='store_true', dest='disasm_only',
                       help='Print modern block-by-block disassembly & CFG view')
    group.add_argument('-de', '--decompile', action='store_true', dest='decompile_only',
                       help='Decompile to high-level C-like language (default)')
    group.add_argument('-da', '--deep', action='store_true', dest='deep_analysis',
                       help='Run deep inter-procedural analysis (XREFs, crypto detection, vulnerability audit, type recovery)')
    parser.add_argument('-f', '--function', dest='target_function', default=None,
                        help='Decompile only a specific function by name or hex address (e.g. -f main or -f 0x40118c)')
    parser.add_argument('-o', '--output', dest='output_file', default=None,
                        help='Save decompiled C code directly to specified file')
    parser.add_argument('--raw', action='store_true', dest='raw_output',
                        help='Output plain text without rich terminal colors or formatting')
    parser.add_argument('filename', help='Path to the binary file to analyze (ELF, PE, Mach-O)')

    args = parser.parse_args()

    decompile_binary(
        filename=args.filename,
        disasm_only=args.disasm_only,
        decompile_only=not (args.disasm_only or args.deep_analysis),
        deep_analysis=args.deep_analysis,
        target_func=args.target_function,
        output_file=args.output_file,
        raw_output=args.raw_output
    )