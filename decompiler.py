import sys
import argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import *
from capstone.x86 import *

class BasicBlock:
    def __init__(self, start_addr, cs, sections_data, symbol_map):
        self.start_addr = start_addr
        self.end_addr = 0
        self.instructions = [] 
        self.successors = []
        self.predecessors = []
        self.tags = set()
        self.cs = cs
        self.sections = sections_data
        self.symbol_map = symbol_map 

        self.regs_read = set()
        self.regs_written = set()
        self.stack_accesses = set()

        self.use = set()
        self.set = set()
        self.live_in = set()
        self.live_out = set()


    def _read_string(self, abs_addr):
        for name, section in self.sections.items():
            if section['addr'] <= abs_addr < section['addr'] + section['size']:
                offset = abs_addr - section['addr']
                data = section['data'][offset:]
                try:
                    null_term_index = data.index(b'\x00')
                    string_data = data[:null_term_index]
                except ValueError:
                    string_data = data[:20] 
                s = string_data.decode('utf-8', 'replace').replace('\n', '\\n').replace('"', '\\"')
                return f'"{s}"'
        return None

    def _resolve_operand(self, instr, op):
        if op.type == CS_OP_REG: return self.cs.reg_name(op.reg)
        if op.type == CS_OP_IMM: return hex(op.imm)
        if op.type == CS_OP_MEM:
            base = self.cs.reg_name(op.mem.base)
            disp = op.mem.disp
            seg = self.cs.reg_name(op.mem.segment)

            if seg == 'fs' and base == 'invalid':
                return f"[fs:{hex(disp)}]"
            
            if base == 'rip':
                target_addr = instr.address + instr.size + disp
                resolved_string = self._read_string(target_addr)
                if resolved_string: return resolved_string
                else: return f"&g_data_{hex(target_addr)}"
            
            if base in ('rsp', 'rbp'):
                if disp == 0: return f"[{base}]"
                elif disp > 0: return f"[{base} + {hex(disp)}]"
                else: return f"[{base} - {hex(-disp)}]"
            
            return f"[{instr.op_str}]" 

        return "UNKNOWN"

    def add_instruction(self, instr):
        self.instructions.append(instr)
        self.end_addr = instr.address + instr.size
        instr.resolved_op_strs = [self._resolve_operand(instr, op) for op in instr.operands]
        
        for reg_id in instr.regs_read: self.regs_read.add(self.cs.reg_name(reg_id))
        for reg_id in instr.regs_write: self.regs_written.add(self.cs.reg_name(reg_id))
        
        for op_str in instr.resolved_op_strs:
            if op_str.startswith('[rsp') or op_str.startswith('[rbp') or op_str.startswith('[fs:'):
                self.stack_accesses.add(op_str)
    def calculate_use_set(self):
        noise_regs = {'rip', 'eip', 'rsp', 'rbp', 'rflags'}
        self.use = (self.regs_read - noise_regs).union(self.stack_accesses)
        self.set = (self.regs_written - noise_regs)

    def print_c_like(self):
        print(f"\nL_{hex(self.start_addr)}:")
        
        last_instr = self.instructions[-1]
        mnemonic = last_instr.mnemonic

        def get_condition_str(jump_instr, prev_instr):
            condition = jump_instr.mnemonic
            prev_resolved_ops = prev_instr.resolved_op_strs
            if prev_instr.mnemonic == 'cmp':
                op1, op2 = prev_resolved_ops
                cond_map = {'je': f"{op1} == {op2}", 'jne': f"{op1} != {op2}", 'jg': f"{op1} > {op2}", 'jge': f"{op1} >= {op2}", 'jl': f"{op1} < {op2}", 'jle': f"{op1} <= {op2}"}
                condition = cond_map.get(mnemonic, mnemonic)
            elif prev_instr.mnemonic == 'test':
                op1, op2 = prev_resolved_ops
                if op1 == op2:
                    if mnemonic == 'jz': condition = f"{op1} == 0"
                    if mnemonic == 'jnz': condition = f"{op1} != 0"
            return condition

        is_loop = 'LOOP_HEADER' in self.tags and 'LOOP_LATCH' in self.tags
        self_jump = any(s.start_addr == self.start_addr for s in self.successors)

        if is_loop and self_jump and mnemonic.startswith('j') and len(self.instructions) > 1:
            exit_successor = next((s for s in self.successors if s.start_addr != self.start_addr), None)
            prev_instr = self.instructions[-2]
            condition = get_condition_str(last_instr, prev_instr)
            
            print("    do {")
            for instr in self.instructions[:-2]: 
                 print(f"        {instr.mnemonic} {', '.join(instr.resolved_op_strs)};")
            print(f"    }} while ({condition});")
            
            if exit_successor:
                print(f"    goto L_{hex(exit_successor.start_addr)};")
            return

        key_instr_count = 0
        for instr in self.instructions:
            if instr.mnemonic not in ('call', 'jmp', 'ret', 'cmp', 'test') and not instr.mnemonic.startswith('j'):
                print(f"    {instr.mnemonic} {', '.join(instr.resolved_op_strs)};")
                key_instr_count += 1
            if key_instr_count > 5 and len(self.instructions) > 8: 
                print(f"    // ... ({len(self.instructions) - key_instr_count} more instructions) ...")
                break
        if mnemonic == 'ret': print("    return;"); return
        if mnemonic == 'jmp':
            if self.successors: print(f"    goto L_{hex(self.successors[0].start_addr)};")
            else: print(f"    // Unresolved jmp ({', '.join(last_instr.resolved_op_strs)})")
            return
        
        if mnemonic == 'call':
            arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            found_args = {}
            for instr in reversed(self.instructions[:-1]):
                if not arg_regs: break
                if instr.mnemonic in ('mov', 'lea'):
                    dest, src = instr.resolved_op_strs
                    if dest in arg_regs:
                        found_args[dest] = src; arg_regs.remove(dest)
            
            call_target_str = last_instr.resolved_op_strs[0]
            call_target_addr = None
            try: call_target_addr = int(call_target_str, 16)
            except ValueError: pass 

            if call_target_addr and call_target_addr in self.symbol_map:
                call_target_str = self.symbol_map[call_target_addr] 
            elif call_target_addr:
                call_target_str = f"L_{hex(call_target_addr)}"
            
            arg_strings = [f"{reg}={found_args[reg]}" for reg in ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'] if reg in found_args]
            print(f"    call {call_target_str}({', '.join(arg_strings)});")
            
            if len(self.successors) == 1:
                print(f"    goto L_{hex(self.successors[0].start_addr)};")
            return

        if mnemonic.startswith('j'):
            condition = get_condition_str(last_instr, self.instructions[-2] if len(self.instructions) > 1 else None)
            if len(self.successors) == 2:
                print(f"    if ({condition}) goto L_{hex(self.successors[0].start_addr)};")
                print(f"    goto L_{hex(self.successors[1].start_addr)};")
            elif len(self.successors) == 1:
                print(f"    if ({condition}) goto L_{hex(self.successors[0].start_addr)};")
            return

        if len(self.successors) == 1:
            print(f"    goto L_{hex(self.successors[0].start_addr)};")

    def print_full_disassembly(self):
        print(f"\n  --- Basic Block at {hex(self.start_addr)} ---")
        for instr in self.instructions:
            print(f"    {hex(instr.address)}:\t{instr.mnemonic}\t{', '.join(instr.resolved_op_strs)}")
        print(f"    ---------------------------------")
        print(f"    [TAGS]: {', '.join(sorted(list(self.tags))) or 'None'}")
        print(f"    [USE]: {', '.join(sorted(list(self.use))) or 'None'}")
        print(f"    [SET]: {', '.join(sorted(list(self.set))) or 'None'}")
        print(f"    [LIVE_IN]: {', '.join(sorted(list(self.live_in))) or 'None'}")
        print(f"    [LIVE_OUT]: {', '.join(sorted(list(self.live_out))) or 'None'}")
        succ_addrs = [hex(s.start_addr) for s in self.successors]
        pred_addrs = [hex(p.start_addr) for p in self.predecessors]
        print(f"    [SUCCESSORS]: {', '.join(sorted(succ_addrs)) or 'None'}")
        print(f"    [PREDECESSORS]: {', '.join(sorted(pred_addrs)) or 'None'}")
        print(f"    [STACK_ACCESS]: {', '.join(sorted(list(self.stack_accesses))) or 'None'}")

def analyze_elf(filename, only_disasm=False, only_decompile=False):
    print(f"[*] Analyzing: {filename}\n")
    try:
        with open(filename, 'rb') as f:
            elf = ELFFile(f)
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True 

            sections_data = {}
            for section in elf.iter_sections():
                if section.name in ('.text', '.rodata', '.data', '.dynsym', '.rela.plt', '.plt'):
                    print(f"[*] Loading section: {section.name}")
                    sections_data[section.name] = {
                        'name': section.name, 
                        'addr': section['sh_addr'],
                        'size': section['sh_size'],
                        'data': section.data()
                    }
            if '.text' not in sections_data: print("[!] No .text section found!"); return
            text = sections_data['.text']
            code_bytes, code_addr = text['data'], text['addr']
            code_end_addr = code_addr + text['size']
            print("--- ELF Header / .text Section (Omitted for brevity) ---")

            symbol_map = {}
            dynsym = elf.get_section_by_name('.dynsym')
            reloc_section = elf.get_section_by_name('.rela.plt')
            plt_section = sections_data.get('.plt', {})
            plt_addr = plt_section.get('addr', 0)
            
            if dynsym and reloc_section and isinstance(reloc_section, RelocationSection) and plt_addr:
                print("[*] Resolving PLT symbols...")
                symbols = list(dynsym.iter_symbols())
                stub_addr = plt_addr + 0x10
                for reloc in reloc_section.iter_relocations():
                    sym_index = reloc['r_info_sym']
                    if sym_index < len(symbols):
                        symbol = symbols[sym_index]
                        sym_name = symbol.name
                        symbol_map[stub_addr] = sym_name
                    stub_addr += 0x10 
            print(f"[*] Symbol map: {symbol_map}")

            function_starts = set()
            if code_addr <= elf.header.e_entry < code_end_addr: function_starts.add(elf.header.e_entry)
            function_starts.add(code_addr)
            for instr in md.disasm(code_bytes, code_addr):
                if instr.mnemonic == "call":
                    try:
                        target_addr = int(instr.op_str, 16)
                        if code_addr <= target_addr < code_end_addr: function_starts.add(target_addr)
                    except ValueError: pass
            for addr in symbol_map.keys():
                function_starts.add(addr)

            print(f"\n--- Decompilation ---")
            sorted_starts = sorted(list(function_starts))
            all_blocks = [] 

            for i, func_addr in enumerate(sorted_starts):
                start_addr = func_addr
                section = None
                
                if '.text' in sections_data and sections_data['.text']['addr'] <= start_addr < sections_data['.text']['addr'] + sections_data['.text']['size']:
                    section = sections_data['.text']
                elif '.plt' in sections_data and sections_data['.plt']['addr'] <= start_addr < sections_data['.plt']['addr'] + sections_data['.plt']['size']:
                    section = sections_data['.plt']
                else:
                    print(f"\n--- Skipping function at {hex(start_addr)} (section not loaded) ---")
                    continue

                func_end_addr_in_section = section['addr'] + section['size']
                next_func_addr = sorted_starts[i+1] if i + 1 < len(sorted_starts) else (section['addr'] + section['size'] + 1)
                end_addr = min(next_func_addr, func_end_addr_in_section)
                
                start_offset = start_addr - section['addr']
                end_offset = end_addr - section['addr']
                func_bytes = section['data'][start_offset:end_offset]

                if not func_bytes: continue

                print(f"\n################################################")
                print(f"\tFunction at {hex(start_addr)} (in {section['name']})")
                print(f"################################################")

                leaders = set(); leaders.add(start_addr) 
                for instr in md.disasm(func_bytes, start_addr):
                    if instr.mnemonic.startswith('j') or instr.mnemonic == 'call':
                        try:
                            target_addr = int(instr.op_str, 16)
                            if start_addr <= target_addr < end_addr: leaders.add(target_addr)
                        except ValueError: pass
                    if instr.mnemonic.startswith('j') or instr.mnemonic in ['call', 'ret']:
                        next_instr_addr = instr.address + instr.size
                        if next_instr_addr < end_addr: leaders.add(next_instr_addr)
                
                sorted_leaders = sorted(list(leaders))
                blocks, block_map = [], {}
                current_block = None
                for instr in md.disasm(func_bytes, start_addr):
                    if instr.address in sorted_leaders:
                        current_block = BasicBlock(instr.address, md, sections_data, symbol_map)
                        blocks.append(current_block); block_map[instr.address] = current_block
                    if current_block: current_block.add_instruction(instr)
                
                for i_block, block in enumerate(blocks):
                    if not block.instructions: continue
                    last_instr, mnemonic = block.instructions[-1], block.instructions[-1].mnemonic
                    next_block = blocks[i_block+1] if i_block + 1 < len(blocks) else None
                    if mnemonic == 'ret': pass 
                    elif mnemonic == 'jmp':
                        try:
                            target_addr = int(last_instr.op_str, 16)
                            if target_addr in block_map: block.successors.append(block_map[target_addr])
                        except ValueError: pass 
                    elif mnemonic.startswith('j'):
                        try:
                            target_addr = int(last_instr.op_str, 16)
                            if target_addr in block_map: block.successors.append(block_map[target_addr])
                            if next_block: block.successors.append(next_block)
                        except ValueError: pass
                    elif mnemonic == 'call':
                        if next_block: block.successors.append(next_block)
                    else:
                        if next_block: block.successors.append(next_block)
                    for succ_block in block.successors:
                        succ_block.predecessors.append(block)

                for block in blocks: block.calculate_use_set()

                changed = True
                while changed:
                    changed = False
                    for block in reversed(blocks):
                        new_live_out = set().union(*[s.live_in for s in block.successors])
                        new_live_in = block.use.union(new_live_out.difference(block.set))
                        if new_live_in != block.live_in or new_live_out != block.live_out:
                            changed = True; block.live_in, block.live_out = new_live_in, new_live_out
                
                for block in blocks:
                    if not block.instructions: continue
                    if len(block.successors) == 2: block.tags.add("IF_STATEMENT")
                    for succ in block.successors:
                        if succ.start_addr <= block.start_addr:
                            block.tags.add("LOOP_LATCH"); succ.tags.add("LOOP_HEADER")
                    if block.instructions[-1].mnemonic == 'ret': block.tags.add("FUNCTION_RETURN")

                # C-like decompilation (higher-level view)
                if not only_disasm:
                    print("\n--- C-Like Control Flow ---")
                    for block in blocks:
                        block.print_c_like()

                # Full disassembly and CFG (lower-level view)
                if not only_decompile:
                    print("\n\n--- Full Disassembly & CFG ---")
                    for block in blocks:
                        block.print_full_disassembly()
                
                all_blocks.extend(blocks)

    except FileNotFoundError:
        print(f"[!] Error: File not found: {filename}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Disassemble and decompile simple ELF x86_64 binaries')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-ds', '--disasm-only', action='store_true', dest='disasm_only', help='Only print full disassembly (skip C-like decompilation)')
    group.add_argument('-de', '--decompile-only', action='store_true', dest='decompile_only', help='Only print C-like decompilation (skip full disassembly)')
    parser.add_argument('filename', help='Path to the ELF file to analyze')
    args = parser.parse_args()

    analyze_elf(args.filename, only_disasm=args.disasm_only, only_decompile=args.decompile_only)
    print("\n\nANALYSIS COMPLETE. YAY!! idk if it showed errors or something, see that yourself.")
    print("This disassembler is made with love <3 \t\t\t- Shiny ★")