"""
===============================================================
    Radium Engine Core (RCE-8b)
    Emulator Skeleton v0.0.2b

    Author: Aidan A. Bradley
    Email: aabradley01@gmail.com

    Last Update: 11/7/26 @ 7:10PM EST
===============================================================
 This module is a Python emulation of the RCE-8b ISA. The ISA
 itself is defined in DOC.md; the self-test suite lives in
 tests.py.
===============================================================
 Features:
    - 16-bit addressing space, little-endian, byte addressable
    - Fixed 16-bit instructions (7-bit opcode, size bit, two
      4-bit register fields)
    - 15 general purpose registers (R0 - R14) plus special
      registers (PC, IP, SP, BP, SIVBR, UIVBR, CTRL, BOOTCFG,
      FLAGS)
    - Two-tiered IVT with system and user IVTs (SIVT, UIVT)
    - Memory mapping with ROM write protection and rejection of
      unmapped and cross-device word accesses
    - Descending stack with byte and word push/pop
    - Fetch/Decode/Execute (non pipelined for now)
    - ALU instructions: NOP, MOV, SWAP, ADD, SUB, INC, DEC, CMP,
      AND, OR, XOR, NOT
    - Zero (Z) and Negative (N) flag updates
===============================================================
 Memory Map:
    0x0000 - 0x5BFF    RESERVED   (reads 0x00, writes rejected)
    0x5C00 - 0xDBFF    RAM        32KB
    0xDC00 - 0xDFFF    MMIO       1KB
    0xE000 - 0xEFFF    USR        4KB User ROM (UIVT at 0xE000)
    0xF000 - 0xFFFF    ROM        4KB Boot ROM (SIVT at 0xF000)
===============================================================
 Instruction Format (16 bits):
    [15:9] opcode    [8] size    [7:4] field A    [3:0] field B

    Two-operand instructions use field A as the source and
    field B as the destination. Single-operand instructions
    (INC, DEC, NOT) use field B.

    Opcode families:
        0x00 - 0x27    ALU
        0x28 - 0x2F    Memory
        0x30 - 0x57    Control
        0x58 - 0x7F    Extended

    Only the ALU family executes at present. Opcodes for LEA,
    MUL, IMUL, DIV, IDIV, NEG, TEST, SHL, SHR, ROL and ROR are
    defined but not yet implemented.
===============================================================
 Flags (FLAGS register, bit positions):
    6:Q  5:TF  4:IF  3:V  2:N  1:Z  0:C
===============================================================
 Interrupts and Reset:
    Each vector table entry is a 16-bit little-endian ISR
    address, so entry n sits at base + (n * 2).

    System vectors: RESET, NMI, TIMER, UART_RX, UART_TX,
                    RESERVED, USER_GATEWAY
    User vectors:   VIDEO, KEYBOARD, TIMER, RESERVED

    resetCPU() clears FLAGS, sets SP = BP = 0xDBFF, loads the
    vector base registers, builds both tables, and loads PC
    from the SYS_RESET entry (0xF100).
===============================================================
 Known Limitations:
    - Only Z and N are updated; C and V are not yet computed
    - No interrupt dispatch (tables are built but not taken)
    - Memory and control instruction families are not executed
    - A failed instruction fetch is not handled in cpuStep()
===============================================================

Importing this module has no side effects. Running it directly
resets the CPU and prints the post-reset state; to run the
self-tests use::

    python tests.py
"""

# =============================================================
#   MEMORY ARCHITECTURE
# =============================================================

#: Total size of the 16-bit address space in bytes.
MEMORY_SIZE = 0x10000

#: Address map as ``(name, start, end)`` tuples. Both bounds are inclusive.
memory_map = [

    ("ROM",      0xF000, 0xFFFF),   # 4KB Boot ROM
    ("USR",      0xE000, 0xEFFF),   # 4KB User ROM
    ("MMIO",     0xDC00, 0xDFFF),   # 1KB MMIO
    ("RAM",      0x5C00, 0xDBFF),   # 32KB RAM
    ("RESERVED", 0x0000, 0x5BFF)    # Remaining is reserved for now

]

# =============================================================
#   MEMORY DEVICES
# =============================================================

#: Backing store for the 4KB Boot ROM (0xF000-0xFFFF).
ROM = [0x0] * (4 * 1024)

#: Backing store for the 4KB User ROM (0xE000-0xEFFF).
USR = [0x0] * (4 * 1024)

#: Backing store for the 1KB MMIO window (0xDC00-0xDFFF).
MMIO = [0x0] * (1 * 1024)

#: Backing store for the 32KB RAM (0x5C00-0xDBFF).
RAM = [0x0] * (32 * 1024)

# =============================================================
#   REGISTER FILE
# =============================================================

#: Number of general purpose registers (R0 - R14).
REGISTER_COUNT = 15

#: General purpose register file.
registers = [0] * REGISTER_COUNT    # initialize registers with zeros

# =============================================================
#   SPECIAL REGISTERS
# =============================================================

#: Special-purpose registers, keyed by name.
special = {

    # Program Flow
    "PC" : 0,
    "IP" : 0,

    # Stack
    "SP" : 0,
    "BP" : 0,

    # Interrupt Tables
    "SIVBR" : 0,        # System Interrupt Vector Base Register (SIVBR)
    "UIVBR" : 0,        # User Interrupt Vector Base Register (UIVBR)

    # Control Registers
    "CTRL" : 0,
    "BOOTCFG" : 0,

    # Status Flags
    "FLAGS" : 0
    # Only 7 bits/7 flags for now
    # ---------------------------------------------------------
    # bit     6      5      4      3      2      1      0
    #         Q      IF     TF     V      N      Z      C
    # ---------------------------------------------------------

}

# =============================================================
#   DEFAULT VECTOR LOCATIONS
# =============================================================

#: Default base address of the System Interrupt Vector Table.
ADDR_SIVBR = 0xF000

#: Default base address of the User Interrupt Vector Table.
ADDR_UIVBR = 0xE000

# =============================================================
#   SYSTEM VECTOR IDS
# =============================================================

SYS_RESET           = 0     #: System vector ID: reset.
SYS_NMI             = 1     #: System vector ID: non-maskable interrupt.
SYS_TIMER           = 2     #: System vector ID: system timer.
SYS_UART_RX         = 3     #: System vector ID: UART receive.
SYS_UART_TX         = 4     #: System vector ID: UART transmit.
SYS_RESERVED        = 5     #: System vector ID: reserved.
SYS_USER_GATEWAY    = 6     #: System vector ID: user-to-system gateway.

# =============================================================
#   USER VECTOR IDS
# =============================================================

USR_VIDEO           = 0     #: User vector ID: video.
USR_KEYBOARD        = 1     #: User vector ID: keyboard.
USR_TIMER           = 2     #: User vector ID: user timer.
USR_RESERVED        = 3     #: User vector ID: reserved.

# =============================================================
#   SYSTEM ISR ADDRESSES
# =============================================================

#: Maps system vector ID to the address of its interrupt service routine.
SYSTEM_ISR_ADDRS = {

    SYS_RESET          : 0xF100,
    SYS_NMI            : 0xF120,
    SYS_TIMER          : 0xF140,
    SYS_UART_RX        : 0xF160,
    SYS_UART_TX        : 0xF180,
    SYS_RESERVED       : 0xF1A0,
    SYS_USER_GATEWAY   : 0xF1C0

}

# =============================================================
#   USER ISR ADDRESSES
# =============================================================

#: Maps user vector ID to the address of its interrupt service routine.
USER_ISR_ADDRS = {

    USR_VIDEO          : 0xE100,
    USR_KEYBOARD       : 0xE120,
    USR_TIMER          : 0xE140,
    USR_RESERVED       : 0xE160

}

# =============================================================
#   FLAG POSITIONS
# =============================================================

FLAG_C                 = 0  #: Carry flag bit position.
FLAG_Z                 = 1  #: Zero flag bit position.
FLAG_N                 = 2  #: Negative flag bit position.
FLAG_V                 = 3  #: Overflow flag bit position.
FLAG_IF                = 4  #: Interrupt-enable flag bit position.
FLAG_TF                = 5  #: Trap flag bit position.
FLAG_Q                 = 6  #: Q flag bit position.

# =============================================================
#   OPCODE GROUPS
# =============================================================

FMT_ALU                = 0  #: Instruction family: ALU / data movement.
FMT_MEMORY             = 1  #: Instruction family: memory access.
FMT_CONTROL            = 2  #: Instruction family: control flow.
FMT_EXTENDED           = 3  #: Instruction family: extended opcodes.

# =============================================================
#   OPCODES (incomplete)
# =============================================================

# Data movement
OP_NOP                 = 0x00   #: No operation.
OP_MOV                 = 0x01   #: Move register to register.
OP_SWAP                = 0x02   #: Swap two registers.
OP_LEA                 = 0x03   #: Load effective address.
OP_MOVI                = 0x04   #: Load immediate value

#Arithmetic
OP_ADD                 = 0x08   #: Add.
OP_SUB                 = 0x09   #: Subtract.

OP_MUL                 = 0x0A   #: Unsigned multiply.
OP_IMUL                = 0x0B   #: Signed multiply.

OP_DIV                 = 0x0C   #: Unsigned divide.
OP_IDIV                = 0x0D   #: Signed divide.

OP_INC                 = 0x0E   #: Increment.
OP_DEC                 = 0x0F   #: Decrement.

OP_NEG                 = 0x10   #: Two's complement negate.

# Logic
OP_AND                 = 0x14   #: Bitwise AND.
OP_OR                  = 0x15   #: Bitwise OR.
OP_XOR                 = 0x16   #: Bitwise XOR.
OP_NOT                 = 0x17   #: Bitwise NOT.

OP_TEST                = 0x18   #: Bitwise AND, flags only.

# Compare
OP_CMP                 = 0x1C   #: Compare, flags only.

# Shift / Rotate
OP_SHL                 = 0x20   #: Shift left.
OP_SHR                 = 0x21   #: Shift right.

OP_ROL                 = 0x22   #: Rotate left.
OP_ROR                 = 0x23   #: Rotate right.

OP_LD                  = 0x28   #: Load value from memory
OP_STR                 = 0x29   #: Store value into memory

OP_PUSH                = 0x2A   #: Push register onto descending stack (sz: 0=byte, 1=word).
OP_POP                 = 0x2B   #: Pop from descending stack into register (sz: 0=byte, 1=word).

OP_PUSHF               = 0x2C   #: Push FLAGS register.
OP_POPF                = 0x2D   #: Pop FLAGS register.
OP_PUSHA               = 0x2E   #: Push all General Purpose Registers (R0 - R14).
OP_POPA                = 0x2F   #: Pop all General Purpose Registers (R14 - R0).

# Control Flow
OP_JMP                 = 0x30   #: Unconditional absolute jump (2-word).
OP_JMPR                = 0x31   #: Unconditional register-indirect jump.
OP_JE                  = 0x32   #: Jump if Equal / Zero (Z = 1).
OP_JNE                 = 0x33   #: Jump if Not Equal / Not Zero (Z = 0).
OP_JL                  = 0x34   #: Jump if Less (Signed: N != V).
OP_JGE                 = 0x35   #: Jump if Greater or Equal (Signed: N == V).
OP_JB                  = 0x36   #: Jump if Below / Carry (Unsigned: C = 1).
OP_JAE                 = 0x37   #: Jump if Above or Equal / No Carry (Unsigned: C = 0).
OP_JA                  = 0x38   #: Jump if Above (Unsigned: C = 0 and Z = 0).
OP_JBE                 = 0x39   #: Jump if Below or Equal (Unsigned: C = 1 or Z = 1).
OP_JO                  = 0x3A   #: Jump if Overflow (V = 1).
OP_JNO                 = 0x3B   #: Jump if No Overflow (V = 0).

# Subroutines & Interrupt Returns
OP_CALL                = 0x3C   #: Absolute subroutine call (2-word).
OP_CALLR               = 0x3D   #: Register-indirect subroutine call.
OP_RET                 = 0x3E   #: Return from subroutine.
OP_IRET                = 0x3F   #: Return from interrupt (restores flags and PC).

# Interrupts & Traps
OP_INT                 = 0x40   #: Software interrupt / trap.

# =============================================================
#   MEMORY HELPERS
# =============================================================

def getMemArea(addr):
    """
    Find the memory map region that contains an address.

    :param int addr: 16-bit address to look up.
    :return: The ``(name, start, end)`` region tuple, or ``None`` if the
        address lies outside every region.
    :rtype: tuple or None
    """
    for region in memory_map:
        name, start, end = region

        if start <= addr <= end:
            return region

    return None

def getMemRegionData(addr, size):
    """
    Resolve an access into a device name and device-relative offsets.

    :param int addr: Starting address of the access.
    :param int size: Number of bytes accessed.
    :return: ``(device_name, rel_start, rel_end)`` where the offsets are
        relative to the start of the device, or ``None`` if the address is
        unmapped or the access runs past the end of its region.
    :rtype: tuple or None
    """
    region = getMemArea(addr)

    if region is None:
        return None

    name, start, end = region

    abs_end = addr + size - 1

    if abs_end > end:
        return None

    rel_start = addr - start
    rel_end = rel_start + size - 1

    return name, rel_start, rel_end

# =============================================================
#   MEMORY ACCESS
# =============================================================

def readByte(addr):
    """
    Read one byte from the address space.

    :param int addr: Address to read.
    :return: The byte value (0-255). Reserved memory reads as ``0x00``.
        ``None`` if the address is unmapped.
    :rtype: int or None
    """
    region = getMemRegionData(addr, 1)

    if region is None:
        return None

    device, rel_addr, _ = region

    if device == "ROM":
        return ROM[rel_addr]

    if device == "USR":
        return USR[rel_addr]

    if device == "MMIO":
        return MMIO[rel_addr]

    if device == "RAM":
        return RAM[rel_addr]

    return 0x00

def readWord(addr):
    """
    Read a little-endian 16-bit word from the address space.

    Reads that touch an unmapped address or span two different devices are
    rejected.

    :param int addr: Address of the low byte.
    :return: The 16-bit value, or ``None`` if the read is rejected.
    :rtype: int or None
    """
    region1 = getMemRegionData(addr, 1)
    region2 = getMemRegionData(addr + 1, 1)

    if region1 is None:
        return None

    if region2 is None:
        return None

    dev1 = region1[0]
    dev2 = region2[0]

    # Reject cross-device reads
    if dev1 != dev2:
        return None

    low = readByte(addr)
    high = readByte(addr + 1)

    return low | (high << 8)

def writeByte(addr, value):
    """
    Write one byte to the address space.

    ROM, reserved and unmapped addresses reject the write.

    :param int addr: Address to write.
    :param int value: Value to store; masked to 8 bits.
    :return: ``True`` if the byte was stored, ``False`` otherwise.
    :rtype: bool
    """
    value &= 0xFF

    region = getMemRegionData(addr, 1)

    if region is None:
        return False

    device, rel_addr, _ = region

    if device == "ROM":
        return False

    if device == "USR":
        USR[rel_addr] = value
        return True

    if device == "MMIO":
        MMIO[rel_addr] = value
        return True

    if device == "RAM":
        RAM[rel_addr] = value
        return True

    return False

def writeWord(addr, value):
    """
    Write a little-endian 16-bit word to the address space.

    Writes that touch an unmapped address or span two different devices are
    rejected before any byte is stored.

    :param int addr: Address of the low byte.
    :param int value: Value to store; masked to 16 bits.
    :return: ``True`` if both bytes were stored, ``False`` otherwise.
    :rtype: bool
    """
    region1 = getMemRegionData(addr, 1)
    region2 = getMemRegionData(addr + 1, 1)

    if region1 is None:
        return False

    if region2 is None:
        return False

    if region1[0] != region2[0]:
        return False

    value &= 0xFFFF

    low = value & 0xFF
    high = (value >> 8) & 0xFF

    ok_low = writeByte(addr, low)
    ok_high = writeByte(addr + 1, high)

    return ok_low and ok_high

# =============================================================
#   STACK OPERATIONS
# =============================================================

def pushByte(value):
    """
    Push one byte onto the stack (SP is pre-decremented by 1).

    :param int value: Value to push; masked to 8 bits.
    :return: None
    """
    special["SP"] -= 1

    writeByte(
        special["SP"],
        value & 0xFF
        )

def popByte():
    """
    Pop one byte from the stack (SP is post-incremented by 1).

    :return: The byte at the top of the stack, or ``None`` if unreadable.
    :rtype: int or None
    """
    value = readByte(
        special["SP"]
        )

    special["SP"] += 1
    return value

def pushWord(value):
    """
    Push a 16-bit word onto the stack (SP is pre-decremented by 2).

    :param int value: Value to push; masked to 16 bits.
    :return: None
    """
    special["SP"] -= 2

    writeWord(
        special["SP"],
        value
        )

def popWord():
    """
    Pop a 16-bit word from the stack (SP is post-incremented by 2).

    :return: The word at the top of the stack, or ``None`` if unreadable.
    :rtype: int or None
    """
    value = readWord(
        special["SP"]
        )

    special["SP"] += 2

    return value

# =============================================================
#   FLAG HELPERS
# =============================================================

def clearFlags():
    """
    Clear every bit of the FLAGS register.

    :return: None
    """
    special["FLAGS"] = 0


# =============================================================
#   IVT HELPERS
# =============================================================

def calcSIVTAddr(index):
    """
    Compute the address of a System IVT entry.

    :param int index: System vector ID (``SYS_*``).
    :return: ``SIVBR + index * 2``.
    :rtype: int
    """
    return special["SIVBR"] + (index * 2)

def calcUIVTAddr(index):
    """
    Compute the address of a User IVT entry.

    :param int index: User vector ID (``USR_*``).
    :return: ``UIVBR + index * 2``.
    :rtype: int
    """
    return special["UIVBR"] + (index * 2)

# =============================================================
#   IVT INITIALIZATION
# =============================================================

def initSIVT():
    """
    Write every System IVT entry (little-endian ISR address) into Boot ROM.

    Requires ``SIVBR`` to point into ROM.

    :return: None
    """
    for vector, isr in SYSTEM_ISR_ADDRS.items():
        vector_addr = calcSIVTAddr(vector)

        rel = vector_addr - 0xF000

        ROM[rel] = isr & 0xFF
        ROM[rel + 1] = (isr >> 8) & 0xFF

def initUIVT():
    """
    Write every User IVT entry (little-endian ISR address) into User ROM.

    Requires ``UIVBR`` to point into the USR region.

    :return: None
    """
    for vector, isr in USER_ISR_ADDRS.items():
        vector_addr = calcUIVTAddr(vector)

        rel = vector_addr - 0xE000

        USR[rel] = isr & 0xFF
        USR[rel + 1] = (isr >> 8) & 0xFF

# =============================================================
#   RESET LOGIC
# =============================================================

def loadResetVector():
    """
    Load PC from the ``SYS_RESET`` entry of the System IVT.

    :return: None
    """
    vector_addr = calcSIVTAddr(
        SYS_RESET
    )

    special["PC"] = readWord(
        vector_addr
    )

def resetCPU():
    """
    Reset the CPU: clear flags, initialise the stack and vector base
    registers, build both IVTs and jump to the reset vector.

    General purpose registers and RAM are not cleared.

    :return: None
    """
    clearFlags()

    special["SP"] = 0xDBFF
    special["BP"] = 0xDBFF

    special["SIVBR"] = ADDR_SIVBR
    special["UIVBR"] = ADDR_UIVBR

    initSIVT()
    initUIVT()

    loadResetVector()

# =============================================================
#   FETCH STAGE
# =============================================================

def fetchInstruction():
    """
    Fetch the 16-bit instruction at PC.

    Latches PC into IP, then advances PC by 2.

    :return: The raw instruction word, or ``None`` if the fetch failed.
    :rtype: int or None
    """
    special["IP"] = special["PC"]

    instruction = readWord(
        special["PC"]
    )

    special["PC"] += 2

    return instruction

# =============================================================
#   DECODE STAGE
# =============================================================

def parseOpInstFmt(opcode):
    """
    Map an opcode to its instruction family.

    :param int opcode: 7-bit opcode.
    :return: One of ``FMT_ALU`` (< 0x28), ``FMT_MEMORY`` (< 0x30),
        ``FMT_CONTROL`` (< 0x58) or ``FMT_EXTENDED``.
    :rtype: int
    """
    if opcode < 0x28:
        return FMT_ALU

    elif opcode < 0x30:
        return FMT_MEMORY

    elif opcode < 0x58:
        return FMT_CONTROL

    return FMT_EXTENDED

def decodeFields(instr):
    """
    Split a raw instruction word into its bit fields.

    Layout: ``[15:9]`` opcode, ``[8]`` size, ``[7:4]`` field A,
    ``[3:0]`` field B.

    :param int instr: 16-bit instruction word.
    :return: ``(opcode, size, fieldA, fieldB)``.
    :rtype: tuple
    """
    opcode = (instr >> 9) & 0x7F
    sz = (instr >> 8 ) & 0x01

    fieldA = (instr >> 4) & 0x0F
    fieldB = instr & 0x0F

    return opcode, sz, fieldA, fieldB

def decodeInstruction(instr):
    """
    Decode a raw instruction word into a decoded-instruction dictionary.

    :param int instr: 16-bit instruction word.
    :return: Dictionary with keys ``opcode``, ``size``, ``fieldA``,
        ``fieldB`` and ``family``.
    :rtype: dict
    """

    opcode, sz, a, b = decodeFields(instr)

    return {

        "opcode": opcode,
        "size": sz,

        "fieldA": a,
        "fieldB": b,

        "family": parseOpInstFmt(opcode)

    }

# =============================================================
#   EXECUTE STAGE
# =============================================================

def execALUOp(decoded):
    """
    Execute an ALU-family instruction.

    Implemented: NOP, MOV, SWAP, ADD, SUB, INC, DEC, CMP, AND, OR, XOR, NOT.
    Register operands: field A is the source, field B is the destination
    (single-operand instructions use field B).

    :param dict decoded: Output of :func:`decodeInstruction`.
    :return: ``True`` if the instruction executed, ``False`` if the opcode
        is unimplemented or an operand is invalid.
    :rtype: bool
    """

    opcode = decoded["opcode"]

    #
    # NOP
    #
    if opcode == OP_NOP:
        return True

    #
    # LEA (Load Effective Address: Base Register + 16-bit literal offset -> Destination Reg)
    # Encoded with Base Register in fieldA, Destination Register in fieldB, followed by 16-bit offset word.
    #
    elif opcode == OP_LEA:
        base_reg = decoded["fieldA"]
        dst_reg = decoded["fieldB"]

        if not validRegister(base_reg) or not validRegister(dst_reg):
            return False

        # 1. Fetch the 16-bit offset/displacement word from the instruction stream
        offset_val = readWord(special["PC"])
        if offset_val is None:
            return False

        # 2. Advance PC past the offset word
        special["PC"] += 2

        # 3. Compute effective address: Base + Offset (masked to 16 bits)
        effective_addr = (registers[base_reg] + offset_val) & 0xFFFF

        # 4. Store effective address in destination register and update Z/N flags
        registers[dst_reg] = effective_addr
        updateZNFlags(effective_addr)

        return True

    #
    # MOV
    #
    elif opcode == OP_MOV:
        regs = getSrcDst(decoded)

        if regs is None:
            return False

        src, dst = regs

        registers[dst] = registers[src]

        return True

    #
    # MOVI (Move Immediate 16-bit literal into target register)
    # Encoded with target register in fieldB, followed by a 16-bit immediate word.
    #
    elif opcode == OP_MOVI:
        dst = decoded["fieldB"]
        if not validRegister(dst):
            return False

        # 1. Fetch the 16-bit literal word sitting immediately after the instruction stream
        imm_val = readWord(special["PC"])
        if imm_val is None:
            return False

        # 2. Advance PC by 2 bytes to skip over the immediate value
        special["PC"] += 2

        # 3. Load into destination register and update Z and N flags
        registers[dst] = imm_val
        updateZNFlags(imm_val)

        return True

    #
    # SWAP
    #
    elif opcode == OP_SWAP:
        regs = getSrcDst(decoded)

        if regs is None:
            return False

        src, dst = regs

        registers[src], registers[dst] = \
            registers[dst], registers[src]

        return True

    #
    # ADD
    #
    elif opcode == OP_ADD:
        regs = getSrcDst(decoded)

        if regs == None:
            return False

        src, dst = regs

        src_val = registers[src]
        dst_val = registers[dst]

        raw_result = dst_val + src_val
        result = raw_result & 0xFFFF

        # 1. Handle Carry flag (Unsigned overflow, bit 0 / FLAG_C)
        if raw_result > 0xFFFF:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        # 2. Handle Overflow flag (Signed two's-complement overflow, bit 3 / FLAG_V)
        # Overflow happens if adding two numbers of the same sign yields a result with the opposite sign
        src_sign = (src_val >> 15) & 1
        dst_sign = (dst_val >> 15) & 1
        res_sign = (result >> 15) & 1

        if (dst_sign == src_sign) and (res_sign != dst_sign):
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_V)

        registers[dst] = result

        # Updates Z and N flags as usual
        updateZNFlags(result)

        return True

    #
    # SUB 
    #
    elif opcode == OP_SUB:
        regs = getSrcDst(decoded)

        if regs == None:
            return False

        src, dst = regs

        src_val = registers[src]
        dst_val = registers[dst]

        raw_result = dst_val - src_val
        result = raw_result & 0xFFFF

        # 1. Handle Carry / Borrow flag (Bit 0 / FLAG_C)
        # Unsigned borrow occurs if src > dst (i.e., raw_result < 0)
        if raw_result < 0:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        # 2. Handle Overflow flag (Signed two's-complement overflow, Bit 3 / FLAG_V)
        # Overflow happens if operands have opposite signs AND the result sign differs from destination sign
        src_sign = (src_val >> 15) & 1
        dst_sign = (dst_val >> 15) & 1
        res_sign = (result >> 15) & 1

        if (dst_sign != src_sign) and (res_sign != dst_sign):
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_V)

        registers[dst] = result

        # Updates Z and N flags as usual
        updateZNFlags(result)

        return True

    #
    # INC
    #
    elif opcode == OP_INC:
        dst = decoded["fieldB"]

        if not validRegister(dst):
            return False

        orig_val = registers[dst]
        raw_result = orig_val + 1
        result = raw_result & 0xFFFF

        # 1. Handle Carry flag (Unsigned overflow past 0xFFFF)
        if raw_result > 0xFFFF:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        # 2. Handle Overflow flag (Signed overflow when 0x7FFF becomes 0x8000)
        # 0x7FFF (+32767) + 1 becomes 0x8000 (-32768), which triggers signed overflow
        if orig_val == 0x7FFF:
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_V)

        registers[dst] = result

        updateZNFlags(result)

        return True

    #
    # DEC
    #
    elif opcode == OP_DEC:
        dst = decoded["fieldB"]

        if not validRegister(dst):
            return False

        orig_val = registers[dst]
        raw_result = orig_val - 1
        result = raw_result & 0xFFFF

        # 1. Handle Carry / Borrow flag (Underflow below 0)
        if raw_result < 0:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        # 2. Handle Overflow flag (Signed overflow when 0x8000 becomes 0x7FFF)
        if orig_val == 0x8000:
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_V)

        registers[dst] = result

        updateZNFlags(result)

        return True

    #
    # CMP 
    #
    elif opcode == OP_CMP:
        regs = getSrcDst(decoded)

        if regs == None:
            return False

        src, dst = regs

        src_val = registers[src]
        dst_val = registers[dst]

        raw_result = dst_val - src_val
        result = raw_result & 0xFFFF

        # 1. Handle Carry / Borrow flag (Bit 0 / FLAG_C)
        if raw_result < 0:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        # 2. Handle Overflow flag (Signed two's-complement overflow, Bit 3 / FLAG_V)
        src_sign = (src_val >> 15) & 1
        dst_sign = (dst_val >> 15) & 1
        res_sign = (result >> 15) & 1

        if (dst_sign != src_sign) and (res_sign != dst_sign):
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_V)

        # CMP only updates flags; the destination is left untouched.
        updateZNFlags(result)

        return True

    #
    # AND
    #
    elif opcode == OP_AND:
        regs = getSrcDst(decoded)

        if regs == None:
            return False

        src, dst = regs

        result = (
            registers[dst] & registers[src]
        ) & 0xFFFF

        registers[dst] = result

        updateLogicFlags(result)

        return True

    #
    # OR
    #
    elif opcode == OP_OR:
        regs = getSrcDst(decoded)

        if regs == None:
            return False

        src, dst = regs

        result = (
            registers[dst] | registers[src]
        ) & 0xFFFF

        registers[dst] = result

        updateLogicFlags(result)

        return True

    #
    # XOR
    #
    elif opcode == OP_XOR:
        regs = getSrcDst(decoded)

        if regs == None:
            return False

        src, dst = regs

        result = (
            registers[dst] ^ registers[src]
        ) & 0xFFFF

        registers[dst] = result

        updateLogicFlags(result)

        return True

    #
    # NOT
    #
    elif opcode == OP_NOT:
        dst = decoded["fieldB"]

        if not validRegister(dst):
            return False

        result = (
            ~registers[dst]
        ) & 0xFFFF

        registers[dst] = result

        updateLogicFlags(result)

        return True

    return False

    #
    # SHL (Shift Left by 1)
    #
    elif opcode == OP_SHL:
        dst = decoded["fieldB"]
        if not validRegister(dst):
            return False

        val = registers[dst]
        
        # Bit 15 goes into Carry
        if val & 0x8000:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        result = (val << 1) & 0xFFFF
        registers[dst] = result
        updateLogicFlags(result)  # Sets Z and N, clears V
        return True

    #
    # SHR (Shift Right by 1)
    #
    elif opcode == OP_SHR:
        dst = decoded["fieldB"]
        if not validRegister(dst):
            return False

        val = registers[dst]
        
        # Bit 0 goes into Carry
        if val & 0x1:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        result = val >> 1
        registers[dst] = result
        updateLogicFlags(result)
        return True

    #
    # ROL (Rotate Left by 1)
    #
    elif opcode == OP_ROL:
        dst = decoded["fieldB"]
        if not validRegister(dst):
            return False

        val = registers[dst]
        
        # Check bit 15 before shifting
        old_msb = (val >> 15) & 1

        # Shift left by 1, mask to 16 bits, and wrap old MSB into bit 0
        result = ((val << 1) & 0xFFFF) | old_msb

        # Set Carry flag if MSB was 1, else clear it
        if old_msb:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        registers[dst] = result
        updateLogicFlags(result)
        return True

    #
    # ROR (Rotate Right by 1)
    #
    elif opcode == OP_ROR:
        dst = decoded["fieldB"]
        if not validRegister(dst):
            return False

        val = registers[dst]
        
        # Check bit 0 before shifting
        old_lsb = val & 1

        # Shift right by 1 and wrap old LSB into bit 15 (0x8000)
        result = (val >> 1) | (old_lsb << 15)

        # Set Carry flag if LSB was 1, else clear it
        if old_lsb:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        registers[dst] = result
        updateLogicFlags(result)
        return True

    #
    # NEG (Two's complement negate)
    #
    elif opcode == OP_NEG:
        dst = decoded["fieldB"]

        if not validRegister(dst):
            return False

        val = registers[dst]

        # Invert bits and add 1 (masked to 16 bits)
        raw_result = (-val)
        result = raw_result & 0xFFFF

        # 1. Carry Flag: set for any non-zero value, cleared if negating 0
        if val != 0:
            setFlag(FLAG_C)
        else:
            clearFlag(FLAG_C)

        # 2. Overflow Flag: set when negating 0x8000 (-32768) because 
        # +32768 exceeds 16-bit signed range
        if val == 0x8000:
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_V)

        registers[dst] = result
        updateZNFlags(result)

        return True

    #
    # MUL (Unsigned Multiply: dst * src -> R15:dst)
    #
    elif opcode == OP_MUL:
        regs = getSrcDst(decoded)

        if regs is None:
            return False

        src, dst = regs

        val_src = registers[src]
        val_dst = registers[dst]

        # 32-bit unsigned product
        product = val_dst * val_src

        low_word = product & 0xFFFF
        high_word = (product >> 16) & 0xFFFF

        # Store low word in dst, high word in R15 (index 15)
        registers[dst] = low_word
        registers[15] = high_word

        # C and V flags set if upper 16 bits are non-zero (significant upper bits exist)
        if high_word != 0:
            setFlag(FLAG_C)
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_C)
            clearFlag(FLAG_V)

        updateZNFlags(low_word)

        return True

    #
    # IMUL (Signed Multiply: dst * src -> R15:dst)
    #
    elif opcode == OP_IMUL:
        regs = getSrcDst(decoded)

        if regs is None:
            return False

        src, dst = regs

        # Interpret 16-bit values as signed two's complement integers
        val_src = registers[src] if registers[src] < 0x8000 else registers[src] - 0x10000
        val_dst = registers[dst] if registers[dst] < 0x8000 else registers[dst] - 0x10000

        # 32-bit signed product
        product = val_dst * val_src

        low_word = product & 0xFFFF
        high_word = (product >> 16) & 0xFFFF

        registers[dst] = low_word
        registers[15] = high_word

        # For IMUL, C and V set if high_word is NOT a simple sign extension of low_word
        expected_sign_ext = 0xFFFF if (low_word & 0x8000) else 0x0000
        if high_word != expected_sign_ext:
            setFlag(FLAG_C)
            setFlag(FLAG_V)
        else:
            clearFlag(FLAG_C)
            clearFlag(FLAG_V)

        updateZNFlags(low_word)

        return True

    #
    # DIV (Unsigned Division: dst / src -> Quotient: dst, Remainder: R15)
    #
    elif opcode == OP_DIV:
        regs = getSrcDst(decoded)

        if regs is None:
            return False

        src, dst = regs

        divisor = registers[src]
        dividend = registers[dst]

        # Divide-by-zero check (Fault hazard)
        if divisor == 0:
            return False

        quotient = (dividend // divisor) & 0xFFFF
        remainder = (dividend % divisor) & 0xFFFF

        registers[dst] = quotient
        registers[15] = remainder

        # Logic flags: C and V cleared for standard division
        clearFlag(FLAG_C)
        clearFlag(FLAG_V)

        updateZNFlags(quotient)

        return True

    #
    # IDIV (Signed Division: dst / src -> Quotient: dst, Remainder: R15)
    #
    elif opcode == OP_IDIV:
        regs = getSrcDst(decoded)

        if regs is None:
            return False

        src, dst = regs

        raw_src = registers[src]
        raw_dst = registers[dst]

        if raw_src == 0:
            return False

        # Convert 16-bit to Python signed ints
        divisor = raw_src if raw_src < 0x8000 else raw_src - 0x10000
        dividend = raw_dst if raw_dst < 0x8000 else raw_dst - 0x10000

        # Truncate towards zero (C/x86 convention for signed integer division)
        quotient_signed = int(dividend / divisor)
        remainder_signed = dividend - (quotient_signed * divisor)

        quotient = quotient_signed & 0xFFFF
        remainder = remainder_signed & 0xFFFF

        registers[dst] = quotient
        registers[15] = remainder

        clearFlag(FLAG_C)
        clearFlag(FLAG_V)

        updateZNFlags(quotient)

        return True

# =============================================================
#    MEMORY FAMILY EXECUTION
# =============================================================

def execMemoryOp(decoded):
    """
    Execute a Memory-family instruction (LD, STR).

    Opcodes:
        - OP_LD (0x28): Load from memory address in Field A into register in Field B.
        - OP_STR (0x29): Store register in Field B into memory address in Field A.
    
    Size bit:
        - size = 0: Byte operation (8-bit)
        - size = 1: Word operation (16-bit)

    :param dict decoded: Output of :func:`decodeInstruction`.
    :return: ``True`` if the instruction executed successfully, ``False`` otherwise.
    :rtype: bool
    """
    opcode = decoded["opcode"]
    sz = decoded["size"]
    
    # Extract pointer source (Field A) and data target/source (Field B)
    regs = getSrcDst(decoded)
    if regs is None:
        return False

    ptr_reg, data_reg = regs
    addr = registers[ptr_reg]

    #
    # OP_LD (Load from memory)
    #
    if opcode == OP_LD:
        if sz == 1:
            # Word Load (16-bit)
            val = readWord(addr)
            if val is None:
                return False  # Unmapped or cross-device word violation
            registers[data_reg] = val
            updateZNFlags(val)
        else:
            # Byte Load (8-bit, zero-extended to 16 bits)
            val = readByte(addr)
            if val is None:
                return False  # Unmapped address
            registers[data_reg] = val & 0xFF
            updateZNFlags(val & 0xFF)

        return True

    #
    # OP_STR (Store to memory)
    #
    elif opcode == OP_STR:
        val = registers[data_reg]

        if sz == 1:
            # Word Store (16-bit)
            success = writeWord(addr, val)
            if not success:
                return False  # ROM write-protection, unmapped, or cross-device violation
        else:
            # Byte Store (8-bit)
            success = writeByte(addr, val & 0xFF)
            if not success:
                return False  # ROM write-protection or unmapped

        return True

    #
    # PUSH (Push register value onto the descending stack)
    #
    elif opcode == OP_PUSH:
        reg = decoded["fieldB"]
        if not validRegister(reg):
            return False

        val = registers[reg]

        if sz == 1:
            # Word Push (16-bit)
            pushWord(val)
        else:
            # Byte Push (8-bit)
            pushByte(val & 0xFF)

        return True

    #
    # POP (Pop value from descending stack into register)
    #
    elif opcode == OP_POP:
        reg = decoded["fieldB"]
        if not validRegister(reg):
            return False

        if sz == 1:
            # Word Pop (16-bit)
            val = popWord()
            if val is None:
                return False
            registers[reg] = val & 0xFFFF
            updateZNFlags(val & 0xFFFF)
        else:
            # Byte Pop (8-bit, zero-extended)
            val = popByte()
            if val is None:
                return False
            registers[reg] = val & 0xFF
            updateZNFlags(val & 0xFF)

        return True

    #
    # PUSHF (Push FLAGS register onto the descending stack)
    #
    elif opcode == OP_PUSHF:
        pushWord(special["FLAGS"])
        return True

    #
    # POPF (Pop value from descending stack into FLAGS register)
    #
    elif opcode == OP_POPF:
        val = popWord()
        if val is None:
            return False
        special["FLAGS"] = val & 0xFFFF
        return True

    #
    # PUSHA (Push all General Purpose Registers R0 through R14)
    #
    elif opcode == OP_PUSHA:
        for r in range(REGISTER_COUNT):
            pushWord(registers[r])
        return True

    #
    # POPA (Pop all General Purpose Registers R14 down to R0)
    #
    elif opcode == OP_POPA:
        # Temporary buffer to hold popped values in reverse order
        temp_regs = {}
        for r in range(REGISTER_COUNT - 1, -1, -1):
            val = popWord()
            if val is None:
                return False
            temp_regs[r] = val & 0xFFFF

        # Restore registers
        for r in range(REGISTER_COUNT):
            registers[r] = temp_regs[r]

        return True

    return False

# =============================================================
#    CONTROL FAMILY EXECUTION
# =============================================================

def execControlOp(decoded):
    """
    Execute a Control-family instruction (JMP, conditional jumps).

    :param dict decoded: Output of :func:`decodeInstruction`.
    :return: ``True`` if executed successfully, ``False`` otherwise.
    :rtype: bool
    """
    opcode = decoded["opcode"]

    # Helper function to evaluate conditional jump branches
    def evaluate_branch(condition):
        # 1. Fetch the 16-bit target address sitting in the instruction stream
        target_addr = readWord(special["PC"])
        if target_addr is None:
            return False
        
        # 2. Advance PC past the target word regardless
        special["PC"] += 2

        # 3. If condition matches, update PC to jump
        if condition:
            special["PC"] = target_addr

        return True

    #
    # JMP (Unconditional Absolute Jump)
    #
    if opcode == OP_JMP:
        target_addr = readWord(special["PC"])
        if target_addr is None:
            return False
        special["PC"] = target_addr
        return True

    #
    # JMPR (Unconditional Register-Indirect Jump: jump to address in Field B)
    #
    elif opcode == OP_JMPR:
        reg = decoded["fieldB"]
        if not validRegister(reg):
            return False
        special["PC"] = registers[reg]
        return True

    #
    # JE / JZ (Jump if Equal / Zero)
    #
    elif opcode == OP_JE:
        return evaluate_branch(isFlagSet(FLAG_Z))

    #
    # JNE / JNZ (Jump if Not Equal / Not Zero)
    #
    elif opcode == OP_JNE:
        return evaluate_branch(not isFlagSet(FLAG_Z))

    #
    # JL (Jump if Less - Signed: N != V)
    #
    elif opcode == OP_JL:
        n_flag = isFlagSet(FLAG_N)
        v_flag = isFlagSet(FLAG_V)
        return evaluate_branch(n_flag != v_flag)

    #
    # JGE (Jump if Greater or Equal - Signed: N == V)
    #
    elif opcode == OP_JGE:
        n_flag = isFlagSet(FLAG_N)
        v_flag = isFlagSet(FLAG_V)
        return evaluate_branch(n_flag == v_flag)

    #
    # JB / JC (Jump if Below / Carry - Unsigned)
    #
    elif opcode == OP_JB:
        return evaluate_branch(isFlagSet(FLAG_C))

    #
    # JAE / JNC (Jump if Above or Equal / No Carry - Unsigned)
    #
    elif opcode == OP_JAE:
        return evaluate_branch(not isFlagSet(FLAG_C))

    #
    # JA (Jump if Above - Unsigned: C = 0 and Z = 0)
    #
    elif opcode == OP_JA:
        c_flag = isFlagSet(FLAG_C)
        z_flag = isFlagSet(FLAG_Z)
        return evaluate_branch(not c_flag and not z_flag)

    #
    # JBE (Jump if Below or Equal - Unsigned: C = 1 or Z = 1)
    #
    elif opcode == OP_JBE:
        c_flag = isFlagSet(FLAG_C)
        z_flag = isFlagSet(FLAG_Z)
        return evaluate_branch(c_flag or z_flag)

    #
    # JO (Jump if Overflow)
    #
    elif opcode == OP_JO:
        return evaluate_branch(isFlagSet(FLAG_V))

    #
    # JNO (Jump if No Overflow)
    #
    elif opcode == OP_JNO:
        return evaluate_branch(not isFlagSet(FLAG_V))

    #
    # CALL (Absolute Subroutine Call: 2-word instruction)
    #
    elif opcode == OP_CALL:
        # 1. Read the 16-bit target address from the instruction stream
        target_addr = readWord(special["PC"])
        if target_addr is None:
            return False
        
        # 2. Advance PC past the target address word so it points to the return address
        special["PC"] += 2

        # 3. Push the 16-bit return address onto the descending stack
        pushWord(special["PC"])

        # 4. Jump to the subroutine target address
        special["PC"] = target_addr
        return True

    #
    # CALLR (Register-Indirect Subroutine Call)
    #
    elif opcode == OP_CALLR:
        reg = decoded["fieldB"]
        if not validRegister(reg):
            return False

        # 1. Push current PC (already advanced past this 1-word instruction) onto stack
        pushWord(special["PC"])

        # 2. Jump to the address stored in the register
        special["PC"] = registers[reg]
        return True

    #
    # RET (Return from Subroutine)
    #
    elif opcode == OP_RET:
        # 1. Pop the 16-bit return address from the stack
        return_addr = popWord()
        if return_addr is None:
            return False

        # 2. Restore PC to resume execution after the call
        special["PC"] = return_addr
        return True

    #
    # IRET (Return from Interrupt)
    #
    elif opcode == OP_IRET:
        # 1. Pop FLAGS first (since it was pushed last)
        flags_val = popWord()
        
        # 2. Pop return address into PC (since it was pushed first)
        return_addr = popWord()

        if flags_val is None or return_addr is None:
            return False

        special["FLAGS"] = flags_val & 0xFFFF
        special["PC"] = return_addr
        
        return True

    #
    # INT (Software Interrupt / Trap)
    # Encoded with vector ID in fieldB (or lower byte)
    #
    elif opcode == OP_INT:
        vector_index = decoded["fieldB"]

        # Defaulting user-gate or system trap behavior:
        # Let's treat fieldB as a User vector, or route via system gateway if specified.
        success = triggerInterrupt(is_system=False, vector_index=vector_index)
        return success

    return False

# =============================================================
#    INTERRUPT DISPATCH ENGINE
# =============================================================

def triggerInterrupt(is_system, vector_index):
    """
    Dispatch a system or user interrupt:
    1. Resolve vector address from SIVBR or UIVBR.
    2. Read ISR address from the appropriate IVT.
    3. Push current PC and FLAGS onto the stack (Interrupt Stack Frame).
    4. Disable maskable interrupts (clear IF).
    5. Jump PC to the ISR routine.

    :param bool is_system: True for System IVT, False for User IVT.
    :param int vector_index: Vector ID (SYS_* or USR_*).
    :return: ``True`` if dispatched successfully, ``False`` on fault.
    :rtype: bool
    """
    # 1. Resolve IVT entry address
    if is_system:
        vector_addr = calcSIVTAddr(vector_index)
    else:
        vector_addr = calcUIVTAddr(vector_index)

    # 2. Read target ISR address from IVT
    isr_addr = readWord(vector_addr)
    if isr_addr is None:
        return False  # Unmapped or invalid vector table access

    # 3. Push Interrupt Stack Frame (PC first, then FLAGS)
    pushWord(special["PC"])
    pushWord(special["FLAGS"])

    # 4. Clear Interrupt Flag (IF) to disable nested maskable interrupts
    clearFlag(FLAG_IF)

    # 5. Jump PC to the Interrupt Service Routine
    special["PC"] = isr_addr

    return True

def executeInstruction(decoded):
    """
    Dispatch a decoded instruction to the executor for its family.

    :param dict decoded: Output of :func:`decodeInstruction`.
    :return: ``True`` if the instruction executed, ``False`` otherwise.
    :rtype: bool
    """
    family = decoded["family"]

    if family == FMT_ALU:
        return execALUOp(decoded)
    elif family == FMT_MEMORY:
        return execMemoryOp(decoded)
    elif family == FMT_CONTROL:
        return execControlOp(decoded)

    return False

# =============================================================
#   REGISTER / FLAG HELPERS
# =============================================================

def validRegister(reg):
    """
    Check whether a value is a valid general purpose register index.

    :param reg: Candidate register index.
    :return: ``True`` for an integer in ``0 .. REGISTER_COUNT - 1``.
    :rtype: bool
    """
    return (
        isinstance(reg, int)
        and 0 <= reg < REGISTER_COUNT
    )

def setFlag(flag):
    """
    Set one bit of the FLAGS register.

    :param int flag: Flag bit position (``FLAG_*``).
    :return: None
    """
    special["FLAGS"] |= (1 << flag)

def clearFlag(flag):
    """
    Clear one bit of the FLAGS register.

    :param int flag: Flag bit position (``FLAG_*``).
    :return: None
    """
    special["FLAGS"] &= ~(1 << flag)

def isFlagSet(flag):
    """
    Test one bit of the FLAGS register.

    :param int flag: Flag bit position (``FLAG_*``).
    :return: ``True`` if the flag is set.
    :rtype: bool
    """
    return bool(
        special["FLAGS"] & (1 << flag)
    )

def updateZNFlags(result):
    """
    Update the Zero and Negative flags from a 16-bit result.

    :param int result: Result value; masked to 16 bits first.
    :return: None
    """
    result &= 0xFFFF

    #
    # Zero Flag
    #
    if result == 0:
        setFlag(FLAG_Z)
    else:
        clearFlag(FLAG_Z)

    #
    # Negative Flag
    #
    if result & 0x8000:
        setFlag(FLAG_N)
    else:
        clearFlag(FLAG_N)

def updateLogicFlags(result):
    """
    Update flags for logic operations: Zero and Negative reflect the result,
    while Carry and Overflow are explicitly cleared.
    """
    clearFlag(FLAG_C)
    clearFlag(FLAG_V)
    updateZNFlags(result)

def getSrcDst(decoded):
    """
    Extract and validate the source and destination registers.

    :param dict decoded: Output of :func:`decodeInstruction`.
    :return: ``(src, dst)`` taken from field A and field B, or ``None`` if
        either is not a valid register.
    :rtype: tuple or None
    """
    src = decoded["fieldA"]
    dst = decoded["fieldB"]

    if not validRegister(src):
        return None

    if not validRegister(dst):
        return None

    return src, dst

# =============================================================
#   CPU STEP
# =============================================================

def cpuStep():
    """
    Run one fetch/decode/execute cycle (non-pipelined).

    :return: None
    """
    instr = fetchInstruction()
    decoded = decodeInstruction(instr)
    executeInstruction(decoded)

# =============================================================
#   MAIN
# =============================================================
if __name__ == "__main__":
    resetCPU()

    print("RCE-8b emulator: CPU reset")
    print(f"  PC    = 0x{special['PC']:04X}")
    print(f"  SP    = 0x{special['SP']:04X}")
    print(f"  SIVBR = 0x{special['SIVBR']:04X}")
    print(f"  UIVBR = 0x{special['UIVBR']:04X}")
    print(f"  FLAGS = 0x{special['FLAGS']:04X}")