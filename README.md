# Radium Engine Core (RCE-8b)

A custom 16-bit homebrew CPU architecture and Python emulator designed for deterministic, real-time data acquisition and analytical workloads. 

> **Note:** This is a personal pet project exploring custom Instruction Set Architecture (ISA) design, software emulation, and eventual breadboard/PCB hardware realization.

---

## Current Status

- **Emulator Version:** `v0.0.3b` (Implemented in `main.py` & verified by `tests.py`)
- **Documentation (`DOC.md`):** Updated to reflect complete ALU, Memory, Control Flow, and Context management implementations.
- **Architecture Roadmap:** Next phase targets **`v0.0.4b`** (introducing real-time MMIO hardware peripherals, cycle-deterministic execution tracking, privilege separation via `CTRL`, and a two-pass assembler toolchain).

---

## Architecture Overview

- **Address Space:** $64\text{ KB}$ byte-addressable, little-endian memory space.
- **Instruction Format:** Fixed 16-bit instruction words (`[15:9]` Opcode, `[8]` Size bit, `[7:4]` Field A, `[3:0]` Field B) with multi-word extensions (`MOVI`, `LEA`, absolute jumps/calls) for 16-bit constants and displacements.
- **Register File:** 15 General-Purpose Registers (`R0`–`R14`), plus dedicated Special Registers (`PC`, `IP`, `SP`, `BP`, `SIVBR`, `UIVBR`, `CTRL`, `BOOTCFG`, `FLAGS`). `R15` serves as the explicit upper-word/remainder target for 32-bit math.
- **Status Flags:** Complete 7-bit `FLAGS` register handling bit positions: Carry ($C$), Zero ($Z$), Negative ($N$), Overflow ($V$), Interrupt-Enable ($IF$), Trap ($TF$), and Quality ($Q$).
- **Interrupt Architecture:** Dual-tiered System and User Interrupt Vector Tables (`SIVT` anchored at `0xF000`, `UIVT` anchored at `0xE000`) with indivisible interrupt stack frames and `IRET` restoration.

---

## Instruction Set Architecture Summary

### 1. ALU & Arithmetic (`0x00 – 0x27`)
- **Data Movement & Address:** `NOP`, `MOV`, `SWAP`, `LEA`, `MOVI` (multi-word immediate load).
- **Arithmetic & 32-Bit Math:** `ADD`, `SUB`, `MUL` (unsigned product to `R15:dst`), `IMUL` (signed product to `R15:dst`), `DIV` (quotient to `dst`, remainder to `R15`), `IDIV` (signed divide), `INC`, `DEC`, `NEG` (two's complement).
- **Bitwise & Logic:** `AND`, `OR`, `XOR`, `NOT`, `TEST`.
- **Shifts & Rotates:** `SHL`, `SHR`, `ROL`, `ROR` (with Carry flag integration).

### 2. Memory & Stack Operations (`0x28 – 0x2F`)
- **Indirect Access:** `LD` (Load word/byte from `[Field A]` into `Field B`), `STR` (Store word/byte from `Field B` to `[Field A]`).
- **Stack Operations:** `PUSH`, `POP` (descending stack with byte/word size-bit support).
- **Context Handling:** `PUSHF`, `POPF` (FLAGS preservation), `PUSHA`, `POPA` (bulk push `R0`–`R14` / pop `R14`–`R0`).

### 3. Control Flow & Interrupts (`0x30 – 0x57`)
- **Unconditional Jumps:** `JMP` (absolute 2-word jump), `JMPR` (register-indirect jump).
- **Conditional Branches:** Signed (`JL`, `JGE`), Unsigned (`JB`, `JAE`, `JA`, `JBE`), Equality (`JE`, `JNE`), and Overflow (`JO`, `JNO`).
- **Subroutines:** `CALL` (absolute call), `CALLR` (register-indirect call), `RET` (subroutine return).
- **Interrupt Traps:** `INT` (software vector trap), `IRET` (interrupt return restoring `FLAGS` and `PC`).

---

## Memory Map

| Region | Address Range | Size | Description |
| :--- | :--- | :--- | :--- |
| **`RESERVED`** | `0x0000 – 0x5BFF` | $23.5\text{ KB}$ | Reserved space (reads return `0x00`, writes rejected) |
| **`RAM`** | `0x5C00 – 0xDBFF` | $32\text{ KB}$ | High-speed general RAM & System Stack |
| **`MMIO`** | `0xDC00 – 0xDFFF` | $1\text{ KB}$ | Peripheral register window |
| **`USR`** | `0xE000 – 0xEFFF` | $4\text{ KB}$ | User ROM (contains User IVT) |
| **`ROM`** | `0xF000 – 0xFFFF` | $4\text{ KB}$ | Boot ROM (contains System IVT & reset vector) |

---

## Project Layout

```text
├── main.py        # Core emulator engine (Fetch/Decode/Execute pipelines, Memory Bus, Registers)
├── tests.py       # Automated self-test suite (Instruction verification, Memory safety, Stack frames)
├── DOC.md         # Full architecture specification document
└── README.md      # Project overview & roadmap
```