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

def updateLogicFlags(result):
    """
    Update flags for logic operations: Zero and Negative reflect the result,
    while Carry and Overflow are explicitly cleared.
    """
    clearFlag(FLAG_C)
    clearFlag(FLAG_V)
    updateZNFlags(result)

def executeInstruction(decoded):
    """
    Dispatch a decoded instruction to the executor for its family.

    Only the ALU family is implemented so far.

    :param dict decoded: Output of :func:`decodeInstruction`.
    :return: ``True`` if the instruction executed, ``False`` otherwise.
    :rtype: bool
    """
    family = decoded["family"]

    if family == FMT_ALU:
        return execALUOp(decoded)

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