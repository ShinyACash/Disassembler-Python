# Python Disassembler (that also tries to decompile)

This is lowkey a decompiler and static analysis engine for 64-bit ELF binaries, written entirely in Python. I made this for my personal use in CTFs and its just that some decompilers online dont work above 2mb size and the fact that I can literally add my own features into this makes it interesting for me.
 
</br>

### What I learnt:

1.  **Parsing & Disassembly:** How to read an executable.
2.  **Control Flow Analysis:** How to find functions, blocks, and loops.
3.  **Data Flow Analysis:** How to find strings, global data, and track variable liveness.
4.  **Reconstruction:** How to "lift" low-level assembly into a high-level, human-readable format.

---

## Features

This isn't just a disassembler. It's an analysis engine (sorta).

* **ELF 64-bit Parser**: Loads all critical sections from an ELF file.
* **Dynamic Symbol Resolution**: Reads the PLT and `.dynsym` tables to resolve `call L_0x1110` into `call printf` (at least tries to at its best, might not work)
* **String & Data Resolution**: Resolves `rip-relative` memory accesses into human-readable strings 
* **Control Flow Graph (CFG) Builder**: Automatically builds a full CFG for every function, identifying all basic blocks and their `successors`/`predecessors`.
* **Liveness Analysis**: Performs a full backward data-flow analysis to calculate the `[LIVE_IN]` and `[LIVE_OUT]` sets for every basic block.
* **Structure Reconstruction**: Identifies and "lifts" simple `do-while` loops, replacing messy `goto` spaghetti with a high-level C structure.
* **Predicate Analysis**: Reconstructs `if` statement conditions by mapping `cmp`/`test` instructions to their corresponding jumps
* **Dual-View Output**: Provides two views for every function:
    1.  **C-Like Control Flow**: A high-level, human-readable view of the program's logic.
    2.  **Full Disassembly & CFG**: A detailed, "under-the-hood" view showing all analysis data for each block.
* More to come in the future if I feel like working on it based off of my CTF preferences.

---

## Installation and How to Use?

This tool relies on two key libraries: `pyelftools` for parsing the ELF file and `capstone` for the core disassembly.

```bash
pip install pyelftools capstone
```

* Make sure that the elf file you are trying to disassemble is in the same directory as the python file.
### Run :
```bash
python decompiler.py <elf-file>
```

* `python decompiler.py -ds <elf-file>` for only displaying disassembled code.
* `python decompiler.py -de <elf-file>` for only displaying possible C like control flow.
* for help run `python decompiler.py -help`

## Things to note:
* This is still under development and may come accross errors when disassembling/decompiling. Disassembling shouldnt be a problem but there may be errors in decompiling to C like code.
