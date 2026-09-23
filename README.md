# declaw - Universal Binary Decompiler & Binary Analysis Engine

An advanced, lightweight executable decompiler and static analysis engine written in Python. Built for reverse engineering and CTF competitions, it transforms raw machine code from ELF (Linux), PE (Windows), and Mach-O (macOS) binaries into clean, structured, and idiomatic C code, often producing output that is more readable and intuitive than Ghidra or IDA Pro.

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
# Decompile all functions to clean C with syntax highlighting (Default mode)
python declaw.py binary_file

# Decompile a specific function (by name or hex address)
python declaw.py binary_file -f main

# View modernized block-by-block disassembly & CFG view with inlined annotations
python declaw.py binary_file -dasm -f main

# Run Deep Inter-Procedural Analysis (mitigations, crypto detection, vuln audit, call graphs)
python declaw.py binary_file -da

# Export decompiled C code directly to a file
python declaw.py binary_file -f main -o output.c

# Output plain text without ANSI terminal formatting (for piping / grep)
python declaw.py binary_file -f main --raw
```

### Command-Line Options

| Flag | Full Option | Description |
| :--- | :--- | :--- |
| *(default)* | | Decompile binary to structured C-like code with syntax highlighting |
| `-dasm`, `-ds` | `--disasm` | Display modern block-by-block disassembly, lifted C statements, and CFG panels |
| `-da` | `--deep` | Run deep analysis: security mitigations, crypto constant detection, vuln audit & complexity |
| `-de` | `--decompile` | Explicitly request C decompilation (same as default) |
| `-f` | `--function` | Target a specific function by symbol name (e.g. `main`) or hex address (e.g. `0x401120`) |
| `-o` | `--output` | Save the generated C code into a `.c` file complete with standard headers |
| `--raw` | `--raw` | Emit plain text output without Rich terminal panels or color codes |
| `-h` | `--help` | Show command-line help message |

---

## Analysis Modes

### 1. High-Level C Decompilation (Default)
Emits structured C code without compiler artifacts, stack canary checks, or unnecessary `goto` statements. Folds expressions, recovers loops (`for`, `while`), resolves jump tables (`switch-case`), and infers buffer types.

### 2. Modern Block-by-Block Disassembly (`-dasm`)
Designed for low-level reverse engineering with maximum terminal clarity:
* **Styled Basic Block Panels:** Color-coded rounded boxes (green entry, magenta exit, bright blue intermediate).
* **Syntax Color-Coded Mnemonics:** Calls/jumps in yellow, arithmetic/logic in green, data movement in cyan, comparisons in red.
* **Inlined Semantic Annotations:** Automatically resolves branch targets, call targets (`➔ printf()`), strings (`"Enter key: "`), and global symbols (`&stdin`).
* **Lifted C Statements & CFG Details:** Displays lifted C logic per block alongside Jump Type, Taken/Fall branches, and Predecessors with directional connecting flow arrows.

### 3. Deep Inter-Procedural Analysis (`-da` / `--deep`)
Performs thorough multi-pass static binary auditing:
* **Binary Mitigations:** Audits NX/DEP, PIE/ASLR, Stack Canary (`fs:[0x28]`), RELRO (Full / Partial / None), and stripped symbol state.
* **Shannon Section Entropy:** Detects packed, compressed, or encrypted sections ($\ge 6.8$ bits/byte).
* **CTF Logic & Flag Detection:** Surfaces Base64 secrets, hardcoded flag strings, stack strings, authorization routines, and win functions.
* **User-Defined Global Variable Enumeration:** Tracks variables across `.data`, `.bss`, and `.rodata` with initial values, roles, and referencing functions.
* **Cryptographic & Math Constant Detection:** Identifies TEA/XTEA deltas (`0x9e3779b9`, `0x61c88647`), MD5/SHA-1 states, SHA-256 rounds, CRC32 polynomials (`0xedb88320`), LFSR seeds (`0x13579bdf`), custom cipher constants (`0xf5a4ada5`), and Base64 tables.
* **Vulnerability & Anti-Analysis Audit:** Flags format string bugs (`printf(&var)`), dangerous calls (`gets()`), unbounded string functions (`strcpy`, `sprintf`), and anti-debugging checks (`ptrace`).
* **Complexity & Call Graphs:** Calculates McCabe cyclomatic complexity $M = E - N + 2$, caller/callee cross-references, and prepends threat-intel headers to decompiled C functions.

---

## Example Output

Decompiling the `menu` function from a switch-case binary (`challenge`):

```c
// ==================== menu (0x40124b) ====================
int menu() {
    int var_8 = 0;

    print_menu();
    __isoc99_scanf("%d", &var_8);
    switch (var_8) {
        case 0:
            puts("You are a real hacker!");
            break;
        case 1:
            vuln();
            break;
        case 2:
            secret();
            break;
        case 3:
            puts("Good Bye!");
            exit(0);
            break;
        default:
            puts("Invalid choice!");
            break;
    }
    return;
}
```

Decompiling `imperial_archive` (32-bit ELF with full argument recovery):

```c
// ==================== main (0x80493f2) ====================
int main(int argc, char **argv) {
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    puts("=== Mauryan Royal Archive v1.0 ===");
    scribe_function();
    return 0;
}
```

---

## License

MIT License. Designed and maintained for CTF competitors, security analysts, and reverse engineers.
