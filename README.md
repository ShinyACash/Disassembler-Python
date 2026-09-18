# declaw - Universal Binary Decompiler & Binary Analysis Engine

An advanced, lightweight executable decompiler and static analysis engine written in Python. Built for reverse engineering and CTF competitions, it transforms raw machine code from ELF (Linux), PE (Windows), and Mach-O (macOS) binaries into clean, structured, and idiomatic C code—often producing output that is more readable and intuitive than Ghidra or IDA Pro.

---

## Why declaw Outperforms Heavy GUI Tools in CTFs

Traditional tools like Ghidra and IDA Pro produce cluttered pseudo-C filled with artificial compiler artifacts, unrolled pointer arithmetic, unpropagated stack variables, and `goto` spaghetti. declaw addresses these issues directly:

| Feature | Ghidra / IDA Pro Default Pseudo-C | declaw |
| :--- | :--- | :--- |
| **Startup Time** | 15–45 seconds (heavy JVM / workspace load) | **Instant (< 100ms startup)** |
| **Terminal & Headless** | Requires headless script setup or GUI | **Native CLI with Rich syntax highlighting** |
| **Control Flow** | Heavy `goto` spaghetti and condition inversions | **Structured `for`, `while`, `switch-case`, `if-else`** |
| **Stack Canaries** | Leaves `in_FS_OFFSET`, `uVar1 ^ *(long *)(in_FS_OFFSET + 0x28)` | **Completely stripped (prologue & epilogue)** |
| **Stack Realignment** | Obscures main with `lea ecx, [esp+4]; and esp, -16` | **Automatically normalized and stripped** |
| **Calling Conventions** | Leaves spilled register assignments | **Full SysV AMD64 & x86 cdecl argument folding** |
| **Tail Calls** | Disassembles as confusing foreign jumps | **Lifted directly to clean function calls & returns** |
| **Repetitive Zeroing** | Dozens of `var_X = 0; var_Y = 0;` statements | **Collapsed into clean `memset(&var, 0, sizeof(var))`** |
| **Type & Buffer Sizes** | Uninformative `undefined8 local_48` | **Inferred buffers: `char var_110[256]`, `FILE *`** |
| **ASCII Immediates** | Obscure hex numbers like `0x4e4957584b434148` | **Decoded string literals like `"HACKXWIN"`** |

---

## Side-by-Side Comparison

### Ghidra Output vs. declaw

#### Ghidra Pseudo-C:
```c
undefined8 main(void) {
    long in_FS_OFFSET;
    char local_118 [256];
    long local_18;
    
    local_18 = *(long *)(in_FS_OFFSET + 0x28);
    puts("=== Mauryan Royal Archive v1.0 ===");
    fgets(local_118, 0x100, stdin);
    if (local_18 != *(long *)(in_FS_OFFSET + 0x28)) {
        __stack_chk_fail();
    }
    return 0;
}
```

#### declaw Output:
```c
int main(int argc, char **argv) {
    char var_118[256];

    puts("=== Mauryan Royal Archive v1.0 ===");
    fgets(&var_118, 0x100, stdin);
    return 0;
}
```

*(Notice: Zero stack canary noise, accurate buffer sizing, and clean parameter folding.)*

---

## Core Engine Capabilities

### 1. AST-Based Control Flow Structuring
* **`switch-case` Jump Table Recovery:** Disassembles indirect jump tables (`jmp [rax*8 + table_addr]`), validates targets against code sections, and generates clean `switch (expr) { case 0: ... break; }` blocks.
* **Natural Loop Reconstruction:** 
  * Reconstructs standard `for` loops with loop variables, bounds, and increment steps (`for (var_c = 0; var_c <= 7; var_c++)`).
  * Recovers `while (cond)` and infinite `while (1)` event loops with structured `break;` and `continue;` statements.
* **Structured `if-else` Branches:** Identifies branch convergence points and post-dominators to eliminate unnecessary `goto` statements.

### 2. Forward Expression Folding & Argument Propagation
* **AMD64 System V ABI:** Folds argument registers (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`) directly into function calls (`printf("%s", &var_50)`).
* **32-bit x86 cdecl:** Tracks stack pushes (`push 0x100; push eax; call fgets`) and reconstructs the call arguments in natural left-to-right C order (`fgets(&var, 0x100, stdin)`).
* **Return Value Chaining:** Propagates `rax` / `eax` return values directly into subsequent assignments and conditions (`var_8 = fopen(...); if (fgets(...) != 0)`).

### 3. Compiler Boilerplate Elimination
* **Stack Canary Stripping:** Automatically identifies canary initialization (`fs:[0x28]`) and epilogue checks (`__stack_chk_fail`), removing them completely from decompiled logic.
* **Preamble & Frame Setup Normalization:** Filters stack pointer alignment (`and esp, -16`, `lea ecx, [esp + 4]`), frame pointer setups (`push rbp; mov rbp, rsp`), and callee-saved register pushes/pops.
* **Repetitive Zeroing Collapsing:** Identifies consecutive zero-initializations of stack arrays and collapses them into a concise `memset(&var, 0, sizeof(var));`.

### 4. Comprehensive String & Symbol Recovery
* **Cross-Section String Lifting:** Extracts ASCII and UTF-8 strings from `.rodata`, `.rdata`, `.data`, and `.data.rel.ro` across both position-dependent and PIE binaries.
* **ASCII Immediate Decoding:** Automatically detects string chunks embedded directly as immediate integers in assembly (e.g., `mov rax, 0x4e4957584b434148` -> `"HACKXWIN"`, `"picoCTF{"`, `"_y3"`).
* **Full PLT Resolution:** Resolves `.plt`, `.plt.sec`, `.plt.got`, CET `bnd jmp` stubs, and dynamic relocations to true imported symbol names (`puts`, `fgets`, `system`).
* **Stripped `main` Detection:** Recovers the true entry address of `main` in stripped ELF binaries by analyzing `_start` arguments passed to `__libc_start_main`.

---

## Installation

Ensure Python 3.9+ is installed, then install the dependencies:

```bash
pip install -r requirements.txt
```

### Dependencies
* **`lief`**: Binary format parsing (ELF, PE, Mach-O, relocations, sections).
* **`capstone`**: Multi-architecture disassembly engine.
* **`rich`**: Terminal formatting and syntax-highlighted C code panels.

---

## Usage

```bash
pip install pyelftools capstone
```

* Make sure that the elf file you are trying to disassemble is in the same directory as the python file.
### Run :
* `python decompiler.py <elf-file>`
* `python decompiler.py -ds <elf-file>` for only displaying disassembled code.
* `python decompiler.py -de <elf-file>` for only displaying possible C like control flow.
* for help run `python decompiler.py -help`

## Things to note:
* This is still under development and mayb come accross errors when disassembling/decompiling. Disassembling shouldnt be a problem but there may be errors in decompiling to C like code.
