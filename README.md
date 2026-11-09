# Radium Engine Core (RCE-8b)

A custom 16-bit homebrew CPU architecture and Python emulator designed for deterministic, real-time data acquisition and analytical workloads. 

> **Note:** This is a personal pet project exploring custom Instruction Set Architecture (ISA) design, software emulation, and eventual breadboard/PCB hardware realization.

---

## Current Status

* **Emulator Version:** `v0.0.2b` (Implemented in `main.py` & verified by `tests.py`)
* **Documentation (`DOC.md`):** Matches Revision `v0.0.2b` to reflect the exact state of the working code.
* **Architecture Roadmap:** Architectural design planning is currently targeting **v0.0.4b** (introducing hard/soft fault vectoring, cycle-deterministic timing, multi-bus memory separation, and fixed-header data structures).

---

## Architecture Overview (v0.0.2b Base)

* **Address Space:** $64\text{ KB}$ byte-addressable, little-endian memory.
* **Instruction Format:** Fixed 16-bit instruction words (7-bit Opcode, 1-bit Size bit, two 4-bit Register fields).
* **Register File:** 15 General-Purpose Registers (`R0`–`R14`), plus dedicated Special Registers (`PC`, `IP`, `SP`, `BP`, `SIVBR`, `UIVBR`, `CTRL`, `BOOTCFG`, `FLAGS`).
* **Interrupt Architecture:** Dual-tiered System and User Interrupt Vector Tables (`SIVT` anchored at `0xF000`, `UIVT` anchored at `0xE000`).
* **ALU Operations:** Implemented instructions include `NOP`, `MOV`, `SWAP`, `ADD`, `SUB`, `INC`, `DEC`, `CMP`, `AND`, `OR`, `XOR`, and `NOT` with Zero ($Z$) and Negative ($N$) flag updates.

### Memory Map

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
├── main.py        # Core emulator logic (Fetch/Decode/Execute, Memory Bus, Registers)
├── tests.py       # Comprehensive self-test suite (Memory bounds, ALU, Pipeline, IVT)
├── DOC.md         # Architecture specification for v0.0.2b (matches main.py)
└── README.md      # Project overview
```

---

## Running the Emulator & Test Suite

The emulator relies purely on standard Python 3 with no external dependencies.

### Inspect CPU Reset State
To initialize the CPU, build the vector tables, load the reset vector, and inspect the default register state:

```bash
python main.py
```

### Run Automated Tests
To run the full suite of memory mapping, instruction decoding, register boundary, and execution tests:

```bash
python tests.py
```

---

## Next Steps (Roadmap to v0.0.4b+)

- [ ] **Control Flow & Branching:** Implement `JMP`, `CALL`, `RET`, and flag-driven conditional jumps (`JZ`, `JNZ`, `JL`, `JG`).
- [ ] **Deterministic Timing Model:** Define exact cycle counts for instruction execution and fault handling.
- [ ] **Hardware Fault Vector Table:** Implement Critical vs. Non-Critical (Hard/Soft) fault routing.
- [ ] **Multi-Bus Memory Separation:** Separate CPU SRAM from DMA streaming slots and off-bus VRAM.
