import sys
from elftools.elf.elffile import ELFFile
from capstone import *

class BasicBlock:
    def __init__(self, start_addr):
        self.start_addr = start_addr
        self.end_addr = 0
        self.instructions = []
        self.regs_read = set()
        self.regs_written = set()
        self.successors = []
        self.predecessors = []

    def add_instruction(self, instr, cs):
        self.instructions.append(instr)
        self.end_addr = instr.address + instr.size
        
        for reg_id in instr.regs_read:
            self.regs_read.add(cs.reg_name(reg_id))
        for reg_id in instr.regs_write:
            self.regs_written.add(cs.reg_name(reg_id))

    def print_c_like(self):
        print(f"\nL_{hex(self.start_addr)}:")
        print(f"    // ... ({len(self.instructions)} instructions) ...")
        
        last_instr = self.instructions[-1]
        mnemonic = last_instr.mnemonic
        
        if mnemonic == 'ret':
            print("    return;")
            return

        if mnemonic == 'jmp':
            if self.successors:
                print(f"    goto L_{hex(self.successors[0].start_addr)};")
            else:
                print(f"    // Unresolved jmp ({last_instr.op_str})")
            return

        if mnemonic.startswith('j'):
            if len(self.successors) == 2:
                print(f"    if ({mnemonic}) goto L_{hex(self.successors[0].start_addr)};")
                print(f"    goto L_{hex(self.successors[1].start_addr)};")
            elif len(self.successors) == 1:
                print(f"    if ({mnemonic}) goto L_{hex(self.successors[0].start_addr)};")
            return
            
        if mnemonic == 'call':
            try:
                target_addr = int(last_instr.op_str, 16)
                print(f"    call L_{hex(target_addr)};")
            except ValueError:
                print(f"    call {last_instr.op_str}; // Indirect call")
        
        if len(self.successors) == 1 and not mnemonic == 'call':
            print(f"    goto L_{hex(self.successors[0].start_addr)};")

    def print_full_disassembly(self):
        print(f"\n  --- Basic Block at {hex(self.start_addr)} ---")
        
        for instr in self.instructions:
            print(f"    {hex(instr.address)}:\t{instr.mnemonic}\t{instr.op_str}")
        
        print(f"    ---------------------------------")
        print(f"    [READS]: {', '.join(sorted(list(self.regs_read)))}")
        print(f"    [WRITES]: {', '.join(sorted(list(self.regs_written)))}")
        
        succ_addrs = [hex(s.start_addr) for s in self.successors]
        pred_addrs = [hex(p.start_addr) for p in self.predecessors]
        print(f"    [SUCCESSORS]: {', '.join(succ_addrs) or 'None'}")
        print(f"    [PREDECESSORS]: {', '.join(pred_addrs) or 'None'}")


def analyze_elf(filename):
    print(f"[*] Analyzing: {filename}\n")
    
    try:
        with open(filename, 'rb') as f:
            elf = ELFFile(f)
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.detail = True 

            text_section = elf.get_section_by_name('.text')
            code_bytes = text_section.data()
            code_addr = text_section['sh_addr']
            code_size = text_section['sh_size']
            code_end_addr = code_addr + code_size
            
            print("--- ELF Header / .text Section (Omitted for brevity) ---")

            function_starts = set()
            if code_addr <= elf.header.e_entry < code_end_addr:
                function_starts.add(elf.header.e_entry)
            function_starts.add(code_addr)
            for instr in md.disasm(code_bytes, code_addr):
                if instr.mnemonic == "call":
                    try:
                        target_addr = int(instr.op_str, 16)
                        if code_addr <= target_addr < code_end_addr:
                            function_starts.add(target_addr)
                    except ValueError: pass

            print("\n--- Dual-View Analysis ---")
            sorted_starts = sorted(list(function_starts))

            for i, func_addr in enumerate(sorted_starts):
                start_addr = func_addr
                end_addr = sorted_starts[i+1] if i + 1 < len(sorted_starts) else code_end_addr
                start_offset = start_addr - code_addr
                end_offset = end_addr - code_addr
                func_bytes = code_bytes[start_offset:end_offset]

                print(f"\n################################################")
                print(f"\t\tFunction at {hex(start_addr)} (Size: {len(func_bytes)} bytes)")
                print(f"################################################")

                leaders = set()
                leaders.add(start_addr) 
                for instr in md.disasm(func_bytes, start_addr):
                    if instr.mnemonic.startswith('j') or instr.mnemonic == 'call':
                        try:
                            target_addr = int(instr.op_str, 16)
                            if start_addr <= target_addr < end_addr:
                                leaders.add(target_addr)
                        except ValueError: pass
                    if instr.mnemonic.startswith('j') or instr.mnemonic in ['call', 'ret']:
                        next_instr_addr = instr.address + instr.size
                        if next_instr_addr < end_addr:
                            leaders.add(next_instr_addr)

                sorted_leaders = sorted(list(leaders))
                blocks = []
                block_map = {}
                
                current_block = None
                for instr in md.disasm(func_bytes, start_addr):
                    if instr.address in sorted_leaders:
                        current_block = BasicBlock(instr.address)
                        blocks.append(current_block)
                        block_map[instr.address] = current_block
                    
                    if current_block: # Added a check for safety
                        current_block.add_instruction(instr, md)
                    else:
                        # ts can happen if the first leader isn't the start_addr
                        # It's a bug, but this check makes it safe
                        pass 

                for i, block in enumerate(blocks):
                    if not block.instructions: continue
                    
                    last_instr = block.instructions[-1]
                    mnemonic = last_instr.mnemonic
                    next_block = blocks[i+1] if i + 1 < len(blocks) else None

                    if mnemonic == 'ret':
                        pass 
                    elif mnemonic == 'jmp':
                        try:
                            target_addr = int(last_instr.op_str, 16)
                            if target_addr in block_map:
                                block.successors.append(block_map[target_addr])
                        except ValueError: pass 
                    elif mnemonic.startswith('j'):
                        try:
                            target_addr = int(last_instr.op_str, 16)
                            if target_addr in block_map:
                                block.successors.append(block_map[target_addr]) 
                            if next_block:
                                block.successors.append(next_block) 
                        except ValueError: pass
                    elif mnemonic == 'call':
                        if next_block:
                            block.successors.append(next_block)
                    else:
                        if next_block:
                            block.successors.append(next_block)

                    for succ_block in block.successors:
                        succ_block.predecessors.append(block)

                print("\n--- C-Like 'Goto' Control Flow ---")
                for block in blocks:
                    block.print_c_like()
                
                print("\n\n--- Full Disassembly & CFG ---")
                for block in blocks:
                    block.print_full_disassembly()

    except FileNotFoundError:
        print(f"[!] Error: File not found: {filename}")
    except Exception as e:
        print(f"[!] An error occurred: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 decompiler.py <path_to_elf/bin_file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    analyze_elf(filename)