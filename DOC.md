# Radium Engine Core (RCE-8b) Instruction Set Architecture

**Revision:** 0.0.2b
**Address space:** 16-bit, byte-addressable
**Byte order:** Little-endian
**Instruction width:** Fixed, 16 bits

This document defines the RCE-8b architecture: the programmer-visible state, the memory model, the instruction encoding, the semantics of each instruction, and the interrupt and reset model. Implementations, whether software emulators or hardware, are realizations of this definition and are not part of it.

Terms used throughout:

* **Defined** means an item has an architected name and encoding.
* **Implemented** means an item also has architected semantics in this revision.
* **Reserved** means an item is set aside for future revisions. Software must not depend on its behavior.

---

## 1. Conventions

* All values are unsigned integers unless a section states otherwise. Bit 0 is the least significant bit.
* A **byte** is 8 bits. A **word** is 16 bits.
* Multi-byte quantities (words, addresses, instruction words) are stored with the low-order byte at the lower address.
* Arithmetic results are taken modulo 2^16. No instruction in this revision produces a result wider than a word.
* Hexadecimal values are written with the `0x` prefix.

---

## 2. Programmer-Visible State

### 2.1 General-Purpose Registers

There are 15 general-purpose registers, `R0` through `R14`, each 16 bits wide. A register is selected by a 4-bit index. Index `15` does not name a register and is reserved.

### 2.2 Special-Purpose Registers

| Register | Width | Function |
| --- | --- | --- |
| `PC` | 16 | Address of the next instruction word to fetch. |
| `IP` | 16 | Address of the instruction most recently fetched. |
| `SP` | 16 | Stack pointer. Selects the top of the stack (Section 5). |
| `BP` | 16 | Base pointer for stack frames. |
| `SIVBR` | 16 | Base address of the System Interrupt Vector Table. |
| `UIVBR` | 16 | Base address of the User Interrupt Vector Table. |
| `CTRL` | 16 | Control register. No fields are defined in this revision. |
| `BOOTCFG` | 16 | Boot configuration register. No fields are defined in this revision. |
| `FLAGS` | 16 | Status flags (Section 2.3). |

### 2.3 Status Flags

`FLAGS` holds the following flags. Bits 15 through 7 are reserved.

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | `C` | Carry |
| 1 | `Z` | Zero |
| 2 | `N` | Negative |
| 3 | `V` | Overflow |
| 4 | `IF` | Interrupt enable |
| 5 | `TF` | Trap (single-step) |
| 6 | `Q` | Saturation indicator |

In this revision only `Z` and `N` are modified by any instruction. The positions of `C`, `V`, `IF`, `TF` and `Q` are defined, but no semantics are assigned to them yet.

---

## 3. Memory Model

### 3.1 Address Space

The address space is 64 KB, `0x0000` through `0xFFFF`. It is partitioned into five contiguous regions that together cover every address exactly once.

| Region | Range | Size | Class |
| --- | --- | --- | --- |
| `RESERVED` | `0x0000 – 0x5BFF` | 23.5 KB | Reserved |
| `RAM` | `0x5C00 – 0xDBFF` | 32 KB | Read/write |
| `MMIO` | `0xDC00 – 0xDFFF` | 1 KB | Read/write, peripheral window |
| `USR` | `0xE000 – 0xEFFF` | 4 KB | Read-only (User ROM) |
| `ROM` | `0xF000 – 0xFFFF` | 4 KB | Read-only (Boot ROM) |

### 3.2 Region Semantics

* **`RESERVED`:** a read returns `0x00`. A write has no effect and is rejected.
* **`RAM`:** general-purpose volatile storage. It holds data and the stack.
* **`MMIO`:** the window reserved for peripheral registers. No peripheral registers are defined in this revision.
* **`ROM`:** read-only. A write has no effect and is rejected. It holds the System Interrupt Vector Table at `0xF000` and the boot firmware.
* **`USR`:** holds the User Interrupt Vector Table at `0xE000` and user code. Its contents are established by the image loaded into it, and software executing from the architected instruction set cannot write it. Section 3.4 states this rule.

### 3.3 Access Rules

* A **byte access** names one address and always lies within a single region.
* A **word access** names the address of its low byte and covers that address and the next one. Word accesses have no alignment requirement.
* A word access must lie entirely within one region. A word access whose two bytes fall in different regions, or whose second byte falls beyond `0xFFFF`, is **rejected**.
* A rejected read produces no value. A rejected write modifies no byte of either region.
* The mechanism by which a rejection is reported to software (fault, exception, status) is not defined in this revision.

### 3.4 Write Permissions

| Region | Byte/word write |
| --- | --- |
| `RESERVED` | Rejected |
| `RAM` | Permitted |
| `MMIO` | Permitted |
| `USR` | Permitted by the memory system; ROM-class contents are normally supplied by the loaded image |
| `ROM` | Rejected |

---

## 4. Instruction Format

### 4.1 Encoding

Every instruction is exactly one 16-bit word.

```
 Bit: 15        9  8  7     4  3     0
     +-----------+--+--------+--------+
     | Opcode(7) |Sz|Field A |Field B |
     +-----------+--+--------+--------+
```

| Field | Bits | Width | Meaning |
| --- | --- | --- | --- |
| Opcode | 15:9 | 7 | Selects the operation. |
| `Sz` | 8 | 1 | Size modifier. |
| Field A | 7:4 | 4 | Source register index for two-operand instructions. |
| Field B | 3:0 | 4 | Destination register index for two-operand instructions, or the target register for single-operand instructions. |

The instruction word is composed as:

```
word = (Opcode << 9) | (Sz << 8) | (FieldA << 4) | FieldB
```

Example: `MOV R1, R2` (source `R1`, destination `R2`) has opcode `0x01`, `Sz = 0`, Field A `1`, Field B `2`, giving the word `0x0212`. It is stored in memory as the byte `0x12` followed by the byte `0x02`.

### 4.2 Operand Conventions

* **Two-operand instructions** read Field A as the source register `src` and Field B as the destination register `dst`.
* **Single-operand instructions** (`INC`, `DEC`, `NOT`) use Field B as the target register and ignore Field A.
* `NOP` ignores Field A and Field B.
* `Sz` has no effect on any implemented instruction in this revision. All implemented operations are 16 bits wide.

### 4.3 Operand Validity

A register index is valid only if it is in the range 0 through 14. An instruction that requires a register operand and is given an invalid index has no effect: no register or flag is modified. The instruction word has still been consumed, so `PC` has already advanced (Section 6.2).

### 4.4 Opcode Families

The opcode space is divided into four families by opcode value.

| Family | Opcode range |
| --- | --- |
| ALU and data movement | `0x00 – 0x27` |
| Memory access | `0x28 – 0x2F` |
| Control flow | `0x30 – 0x57` |
| Extended | `0x58 – 0x7F` |

Only the ALU family has implemented instructions in this revision. The remaining three families are reserved.

---

## 5. Stack Model

The stack is a full, descending, last-in first-out structure in memory, addressed by `SP`.

* A **byte push** first decrements `SP` by 1, then writes the byte at `SP`.
* A **byte pop** first reads the byte at `SP`, then increments `SP` by 1.
* A **word push** first decrements `SP` by 2, then writes the word at `SP`.
* A **word pop** first reads the word at `SP`, then increments `SP` by 2.

Because `SP` is decremented before a push, the most recently pushed item is always at `SP`. Pushes and pops are subject to the access rules of Section 3.3, and the architecture does not impose stack bounds beyond those rules.

After reset, `SP` and `BP` both hold `0xDBFF`, the last address of `RAM`. The first byte push therefore writes to `0xDBFE` and the first word push writes to `0xDBFD`.

No instruction in this revision pushes or pops the stack. The model is defined here for use by the control-flow and interrupt mechanisms.

---

## 6. Execution Model

### 6.1 Instruction Cycle

Instructions execute one at a time, in program order, and each instruction completes before the next begins. The cycle has three steps:

1. **Fetch.** `IP` is loaded with `PC`. The word at `PC` is read. `PC` is then increased by 2.
2. **Decode.** The word is split into Opcode, `Sz`, Field A and Field B per Section 4.1, and the family is determined per Section 4.4.
3. **Execute.** The operation selected by the opcode is performed.

### 6.2 Instructions With No Effect

An instruction has no architectural effect other than the fetch-time update of `IP` and `PC` if any of the following holds:

* its opcode is defined but not implemented (Section 7.1);
* its opcode is unassigned;
* its opcode belongs to the memory, control-flow or extended family;
* a required register operand is invalid (Section 4.3).

No illegal-instruction exception is defined in this revision.

### 6.3 Flag Update Rule

Where an instruction is specified to update `Z` and `N`, the flags are derived from its 16-bit result `r`:

* `Z` is set if `r = 0`, and cleared otherwise.
* `N` is set if bit 15 of `r` is 1, and cleared otherwise.

All other flags are left unchanged. An instruction that does not state a flag update leaves every flag unchanged.

---

## 7. Instruction Set

### 7.1 Opcode Map

| Opcode | Mnemonic | Status |
| --- | --- | --- |
| `0x00` | `NOP` | Implemented |
| `0x01` | `MOV` | Implemented |
| `0x02` | `SWAP` | Implemented |
| `0x03` | `LEA` | Defined |
| `0x08` | `ADD` | Implemented |
| `0x09` | `SUB` | Implemented |
| `0x0A` | `MUL` | Defined |
| `0x0B` | `IMUL` | Defined |
| `0x0C` | `DIV` | Defined |
| `0x0D` | `IDIV` | Defined |
| `0x0E` | `INC` | Implemented |
| `0x0F` | `DEC` | Implemented |
| `0x10` | `NEG` | Defined |
| `0x14` | `AND` | Implemented |
| `0x15` | `OR` | Implemented |
| `0x16` | `XOR` | Implemented |
| `0x17` | `NOT` | Implemented |
| `0x18` | `TEST` | Defined |
| `0x1C` | `CMP` | Implemented |
| `0x20` | `SHL` | Defined |
| `0x21` | `SHR` | Defined |
| `0x22` | `ROL` | Defined |
| `0x23` | `ROR` | Defined |

Every opcode not listed is unassigned. Within the ALU family the unassigned opcodes are `0x04–0x07`, `0x11–0x13`, `0x19–0x1B`, `0x1D–0x1F` and `0x24–0x27`.

Defined opcodes that are not implemented have no semantics in this revision and execute as no-effect instructions (Section 6.2). Their semantic descriptions are given by name only: `LEA` (load effective address), `MUL`/`IMUL` (unsigned/signed multiply), `DIV`/`IDIV` (unsigned/signed divide), `NEG` (two's-complement negate), `TEST` (bitwise AND, flags only), `SHL`/`SHR` (shift), `ROL`/`ROR` (rotate).

### 7.2 Data Movement

**`NOP`** (`0x00`)
No operation. Flags are unchanged.

**`MOV`** (`0x01`), operands `src` (A), `dst` (B)
`dst ← src`. `src` is unchanged. Flags are unchanged. If `src` and `dst` are the same register, there is no change.

**`SWAP`** (`0x02`), operands `src` (A), `dst` (B)
The values of `src` and `dst` are exchanged. Flags are unchanged. If `src` and `dst` are the same register, there is no change.

### 7.3 Arithmetic

**`ADD`** (`0x08`), operands `src` (A), `dst` (B)
`dst ← (dst + src) mod 2^16`. Updates `Z` and `N` from the result.

**`SUB`** (`0x09`), operands `src` (A), `dst` (B)
`dst ← (dst − src) mod 2^16`. Updates `Z` and `N` from the result. A subtraction that would be negative wraps modulo 2^16.

**`INC`** (`0x0E`), operand `dst` (B)
`dst ← (dst + 1) mod 2^16`. Updates `Z` and `N` from the result.

**`DEC`** (`0x0F`), operand `dst` (B)
`dst ← (dst − 1) mod 2^16`. Updates `Z` and `N` from the result.

### 7.4 Logic

**`AND`** (`0x14`), operands `src` (A), `dst` (B)
`dst ← dst AND src`. Updates `Z` and `N` from the result.

**`OR`** (`0x15`), operands `src` (A), `dst` (B)
`dst ← dst OR src`. Updates `Z` and `N` from the result.

**`XOR`** (`0x16`), operands `src` (A), `dst` (B)
`dst ← dst XOR src`. Updates `Z` and `N` from the result. `XOR` of a register with itself yields 0.

**`NOT`** (`0x17`), operand `dst` (B)
`dst ← (NOT dst) mod 2^16`, the bitwise complement over 16 bits. Updates `Z` and `N` from the result.

### 7.5 Compare

**`CMP`** (`0x1C`), operands `src` (A), `dst` (B)
Computes `r = (dst − src) mod 2^16` and updates `Z` and `N` from `r`. `r` is discarded. Neither `dst` nor `src` is modified.

After `CMP`, `Z` is set when the operands are equal. `N` is set when the 16-bit difference has bit 15 set.

### 7.6 Flag Summary

| Instruction | Z | N | C | V | Other |
| --- | --- | --- | --- | --- | --- |
| `NOP`, `MOV`, `SWAP` | – | – | – | – | – |
| `ADD`, `SUB`, `INC`, `DEC` | ✓ | ✓ | – | – | – |
| `AND`, `OR`, `XOR`, `NOT` | ✓ | ✓ | – | – | – |
| `CMP` | ✓ | ✓ | – | – | – |

A check mark means the flag is written from the result. A dash means it is left unchanged.

---

## 8. Interrupt Vector Architecture

### 8.1 Vector Tables

Interrupt service routines are located through two vector tables:

* the **System Interrupt Vector Table (SIVT)**, based at the address in `SIVBR`;
* the **User Interrupt Vector Table (UIVT)**, based at the address in `UIVBR`.

Each table entry is one word holding the address of an interrupt service routine (ISR), stored little-endian. The entry for vector ID `n` is located at:

```
entry address = base register + (n × 2)
```

### 8.2 System Vectors

The SIVT is held in Boot ROM. After reset `SIVBR` holds `0xF000`.

| ID | Name | Default ISR address |
| --- | --- | --- |
| 0 | `SYS_RESET` | `0xF100` |
| 1 | `SYS_NMI` | `0xF120` |
| 2 | `SYS_TIMER` | `0xF140` |
| 3 | `SYS_UART_RX` | `0xF160` |
| 4 | `SYS_UART_TX` | `0xF180` |
| 5 | `SYS_RESERVED` | `0xF1A0` |
| 6 | `SYS_USER_GATEWAY` | `0xF1C0` |

### 8.3 User Vectors

The UIVT is held in User ROM. After reset `UIVBR` holds `0xE000`.

| ID | Name | Default ISR address |
| --- | --- | --- |
| 0 | `USR_VIDEO` | `0xE100` |
| 1 | `USR_KEYBOARD` | `0xE120` |
| 2 | `USR_TIMER` | `0xE140` |
| 3 | `USR_RESERVED` | `0xE160` |

### 8.4 Scope of This Revision

The vector tables, their entry format and their default contents are defined. The reset vector (Section 9) is the only vector that is taken. The mechanism that accepts an interrupt request, saves context, and transfers control to an ISR is reserved, as is the return-from-interrupt operation. The flags `IF` and `TF` have defined positions but no defined effect.

---

## 9. Reset

Reset places the processor in the following state, applied in this order:

1. `FLAGS` ← `0`.
2. `SP` ← `0xDBFF` and `BP` ← `0xDBFF`.
3. `SIVBR` ← `0xF000` and `UIVBR` ← `0xE000`.
4. The SIVT and UIVT hold the default ISR addresses of Sections 8.2 and 8.3.
5. `PC` ← the word at address `SIVBR + (SYS_RESET × 2)`, which is `0xF100`.

Execution then proceeds with the first fetch from the address in `PC`.

Reset does not define the values of `R0` through `R14`, `IP`, `CTRL`, `BOOTCFG`, or the contents of `RAM` and `MMIO`.

---

## 10. Reserved for Future Revisions

The following are not defined in revision 0.0.2b and must not be relied upon:

* semantics of the memory, control-flow and extended opcode families;
* semantics of the defined but unimplemented ALU opcodes (Section 7.1);
* the `C`, `V`, `IF`, `TF` and `Q` flags;
* the bit fields of `CTRL` and `BOOTCFG`;
* the `Sz` modifier;
* reporting of rejected memory accesses and of invalid instructions;
* interrupt acceptance, context save, and return from interrupt;
* peripheral registers within the `MMIO` window;
* alignment requirements for instruction fetch.