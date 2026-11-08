"""
===============================================================
    Radium Engine Core (RCE-8b)
    Emulator Self-Test Suite v0.0.2b

    Author: Aidan A. Bradley
    Email: aabradley01@gmail.com

    Last Update: 11/7/26 @ 7:10PM EST
===============================================================
 Test suite for the RCE-8b emulator in main.py.

 Contents:
    - Test utilities (machine reset, instruction encoder,
      single-instruction runner, ROM program loader)
    - Test framework (result counters, summary printer)
    - Core, instruction and edge-case tests
    - runAllTests(), the single-call orchestrator

 Every test is run after a full resetMachine(), so tests are
 order independent. Run the whole suite with::

    python tests.py

or call runAllTests() from another module. It returns True when
every check passes, and the script exits with status 0 on
success and 1 on failure.

 Note: these are plain functions driven by runAllTests(); they
 expect the per-test machine reset that the orchestrator
 performs.
===============================================================
"""

import sys

from main import *      # emulator state, constants and functions (noqa)

# =============================================================
#   TEST UTILITIES
# =============================================================

def loadNOPTestProgram():
    """
    Place a single NOP at the reset ISR address (0xF100) in Boot ROM.

    :return: None
    """
    rel = 0xF100 - 0xF000

    ROM[rel] = 0x00
    ROM[rel + 1] = 0x00

def resetMachine():
    """
    Return the whole machine to a pristine power-on state.

    Zeroes ROM, USR, MMIO, RAM, the register file and every special
    register. Backing lists are cleared in place so existing references
    stay valid. Call :func:`resetCPU` afterwards to build the IVTs.

    :return: None
    """
    ROM[:] = [0x0] * len(ROM)
    USR[:] = [0x0] * len(USR)
    MMIO[:] = [0x0] * len(MMIO)
    RAM[:] = [0x0] * len(RAM)

    registers[:] = [0] * REGISTER_COUNT

    for key in special:
        special[key] = 0

def encodeInstruction(opcode, sz=0, a=0, b=0):
    """
    Assemble an instruction word (inverse of :func:`decodeFields`).

    :param int opcode: 7-bit opcode.
    :param int sz: Size bit.
    :param int a: Field A (source register for two-operand instructions).
    :param int b: Field B (destination register).
    :return: 16-bit instruction word.
    :rtype: int
    """
    return (
        ((opcode & 0x7F) << 9)
        | ((sz & 0x01) << 8)
        | ((a & 0x0F) << 4)
        | (b & 0x0F)
    )

def runInstruction(opcode, a=0, b=0, sz=0):
    """
    Encode, decode and execute a single instruction (no fetch).

    :param int opcode: 7-bit opcode.
    :param int a: Field A.
    :param int b: Field B.
    :param int sz: Size bit.
    :return: The result of :func:`executeInstruction`.
    :rtype: bool
    """
    word = encodeInstruction(opcode, sz, a, b)
    return executeInstruction(decodeInstruction(word))

def loadProgram(words, addr=0xF100):
    """
    Write instruction words (little-endian) directly into Boot ROM.

    :param list words: 16-bit instruction words.
    :param int addr: Start address inside the ROM region.
    :return: None
    """
    for i, word in enumerate(words):
        rel = (addr - 0xF000) + (i * 2)

        ROM[rel] = word & 0xFF
        ROM[rel + 1] = (word >> 8) & 0xFF

# =============================================================
#   TEST FRAMEWORK
# =============================================================

#: Number of passing checks in the current run.
tests_passed = 0

#: Number of failing checks in the current run.
tests_failed = 0

def testResult(name, condition):
    """
    Record and print the outcome of a single check.

    :param str name: Human-readable check name.
    :param bool condition: ``True`` for pass, anything falsy for fail.
    :return: None
    """
    global tests_passed
    global tests_failed

    if condition:
        tests_passed += 1
        print(f"[PASS] {name}")
    else:
        tests_failed += 1
        print(f"[FAIL] {name}")

def printTestSummary():
    """
    Print the pass/fail totals and an overall verdict.

    :return: None
    """
    print("\n=================================")
    print("    TEST SUMMARY")
    print("=================================")
    
    print(f"PASSED:    {tests_passed}")
    print(f"FAILED:    {tests_failed}")

    if tests_failed == 0:
        print("RESULT:        SUCCESS")
    else:
        print("RESULT:        FAILURE")

def testMemoryMap():
    """
    Verify the memory map is contiguous, gap-free and matches the
    backing store sizes.

    :return: None
    """
    ordered = sorted(memory_map, key=lambda r: r[1])

    testResult("memmap: starts at 0x0000", ordered[0][1] == 0x0000)
    testResult("memmap: ends at 0xFFFF", ordered[-1][2] == 0xFFFF)

    contiguous = all(
        ordered[i + 1][1] == ordered[i][2] + 1
        for i in range(len(ordered) - 1)
    )
    testResult("memmap: contiguous, no gaps or overlaps", contiguous)

    total = sum(end - start + 1 for _, start, end in memory_map)
    testResult("memmap: regions sum to MEMORY_SIZE", total == MEMORY_SIZE)

    for name, backing in (("ROM", ROM), ("USR", USR),
                          ("MMIO", MMIO), ("RAM", RAM)):
        region = next(r for r in memory_map if r[0] == name)
        size = region[2] - region[1] + 1
        testResult(f"memmap: {name} backing size matches region",
                   len(backing) == size)

    probes = [
        (0x0000, "RESERVED"), (0x5BFF, "RESERVED"),
        (0x5C00, "RAM"),      (0xDBFF, "RAM"),
        (0xDC00, "MMIO"),     (0xDFFF, "MMIO"),
        (0xE000, "USR"),      (0xEFFF, "USR"),
        (0xF000, "ROM"),      (0xFFFF, "ROM"),
    ]
    for addr, expected in probes:
        area = getMemArea(addr)
        testResult(f"memmap: getMemArea(0x{addr:04X}) == {expected}",
                   area is not None and area[0] == expected)

    testResult("memmap: getMemArea(0x10000) is None",
               getMemArea(0x10000) is None)
    testResult("memmap: getMemArea(-1) is None", getMemArea(-1) is None)

    data = getMemRegionData(0xDC10, 4)
    testResult("memmap: getMemRegionData relative offsets",
               data == ("MMIO", 0x10, 0x13))
    testResult("memmap: getMemRegionData rejects region overrun",
               getMemRegionData(0xDFFF, 2) is None)

def testMemoryReadWrite():
    """
    Verify byte reads and writes on every device type.

    :return: None
    """
    for name, addr in (("RAM", 0x6000), ("MMIO", 0xDC20), ("USR", 0xE200)):
        testResult(f"rw: {name} write succeeds", writeByte(addr, 0xA5))
        testResult(f"rw: {name} readback", readByte(addr) == 0xA5)

    writeByte(0x6001, 0x1AB)
    testResult("rw: writeByte masks to 8 bits", readByte(0x6001) == 0xAB)

    testResult("rw: ROM write rejected", writeByte(0xF200, 0x55) is False)
    testResult("rw: ROM unchanged after rejected write",
               readByte(0xF200) == 0x00)
    testResult("rw: RESERVED write rejected", writeByte(0x1000, 0x55) is False)
    testResult("rw: RESERVED reads as 0x00", readByte(0x1000) == 0x00)
    testResult("rw: unmapped read is None", readByte(0x10000) is None)
    testResult("rw: unmapped write rejected",
               writeByte(0x10000, 0x55) is False)

def testWordAccess():
    """
    Verify little-endian word reads and writes.

    :return: None
    """
    testResult("word: write succeeds", writeWord(0x6000, 0x1234))
    testResult("word: low byte first (little-endian)",
               readByte(0x6000) == 0x34)
    testResult("word: high byte second (little-endian)",
               readByte(0x6001) == 0x12)
    testResult("word: readback", readWord(0x6000) == 0x1234)

    writeWord(0x6010, 0x1ABCD)
    testResult("word: writeWord masks to 16 bits",
               readWord(0x6010) == 0xABCD)

    testResult("word: unmapped read is None", readWord(0x10000) is None)
    testResult("word: unmapped write rejected",
               writeWord(0x10000, 0x1) is False)

def testStackOperations():
    """
    Verify push/pop for bytes and words, including LIFO ordering.

    :return: None
    """
    resetCPU()

    testResult("stack: SP starts at 0xDBFF", special["SP"] == 0xDBFF)

    pushByte(0xAA)
    testResult("stack: pushByte decrements SP by 1", special["SP"] == 0xDBFE)
    testResult("stack: pushByte stores value", readByte(0xDBFE) == 0xAA)
    testResult("stack: popByte returns value", popByte() == 0xAA)
    testResult("stack: popByte restores SP", special["SP"] == 0xDBFF)

    pushWord(0x1234)
    testResult("stack: pushWord decrements SP by 2", special["SP"] == 0xDBFD)
    testResult("stack: pushWord stores value", readWord(0xDBFD) == 0x1234)
    testResult("stack: popWord returns value", popWord() == 0x1234)
    testResult("stack: popWord restores SP", special["SP"] == 0xDBFF)

    pushWord(0x1111)
    pushWord(0x2222)
    pushWord(0x3333)
    order = [popWord(), popWord(), popWord()]
    testResult("stack: words pop in LIFO order",
               order == [0x3333, 0x2222, 0x1111])

    pushByte(0x1FF)
    testResult("stack: pushByte masks to 8 bits", popByte() == 0xFF)

def testVectorHelpers():
    """
    Verify IVT address calculation.

    :return: None
    """
    resetCPU()

    testResult("vec: SIVBR default", special["SIVBR"] == 0xF000)
    testResult("vec: UIVBR default", special["UIVBR"] == 0xE000)
    testResult("vec: calcSIVTAddr(0)", calcSIVTAddr(0) == 0xF000)
    testResult("vec: calcSIVTAddr(3)", calcSIVTAddr(3) == 0xF006)
    testResult("vec: calcSIVTAddr(SYS_USER_GATEWAY)",
               calcSIVTAddr(SYS_USER_GATEWAY) == 0xF00C)
    testResult("vec: calcUIVTAddr(0)", calcUIVTAddr(0) == 0xE000)
    testResult("vec: calcUIVTAddr(2)", calcUIVTAddr(2) == 0xE004)

    special["SIVBR"] = 0xF400
    testResult("vec: calcSIVTAddr follows SIVBR",
               calcSIVTAddr(1) == 0xF402)

def testIVTInitialization():
    """
    Verify both IVTs hold the correct ISR addresses after reset.

    :return: None
    """
    resetCPU()

    for vector, isr in SYSTEM_ISR_ADDRS.items():
        testResult(f"ivt: SIVT vector {vector} -> 0x{isr:04X}",
                   readWord(calcSIVTAddr(vector)) == isr)

    for vector, isr in USER_ISR_ADDRS.items():
        testResult(f"ivt: UIVT vector {vector} -> 0x{isr:04X}",
                   readWord(calcUIVTAddr(vector)) == isr)

def testCPUReset():
    """
    Verify resetCPU restores a known state from a dirtied one.

    :return: None
    """
    special["FLAGS"] = 0x7F
    special["SP"] = 0x1234
    special["BP"] = 0x4321
    special["PC"] = 0x9999

    resetCPU()

    testResult("reset: flags cleared", special["FLAGS"] == 0)
    testResult("reset: SP initialised", special["SP"] == 0xDBFF)
    testResult("reset: BP initialised", special["BP"] == 0xDBFF)
    testResult("reset: SIVBR initialised", special["SIVBR"] == ADDR_SIVBR)
    testResult("reset: UIVBR initialised", special["UIVBR"] == ADDR_UIVBR)
    testResult("reset: PC loaded from reset vector",
               special["PC"] == SYSTEM_ISR_ADDRS[SYS_RESET])

def testInstructionDecoder():
    """
    Verify field extraction, family classification and decode output.

    :return: None
    """
    word = encodeInstruction(OP_ADD, 1, 0x3, 0x7)
    testResult("decode: decodeFields round-trip",
               decodeFields(word) == (OP_ADD, 1, 0x3, 0x7))

    decoded = decodeInstruction(word)
    testResult("decode: opcode", decoded["opcode"] == OP_ADD)
    testResult("decode: size", decoded["size"] == 1)
    testResult("decode: fieldA", decoded["fieldA"] == 0x3)
    testResult("decode: fieldB", decoded["fieldB"] == 0x7)
    testResult("decode: family", decoded["family"] == FMT_ALU)

    families = [
        (0x00, FMT_ALU),      (0x27, FMT_ALU),
        (0x28, FMT_MEMORY),   (0x2F, FMT_MEMORY),
        (0x30, FMT_CONTROL),  (0x57, FMT_CONTROL),
        (0x58, FMT_EXTENDED), (0x7F, FMT_EXTENDED),
    ]
    for opcode, expected in families:
        testResult(f"decode: family of opcode 0x{opcode:02X}",
                   parseOpInstFmt(opcode) == expected)

def testNOP():
    """
    Verify NOP changes nothing and succeeds.

    :return: None
    """
    registers[0] = 0x1111
    registers[14] = 0x2222
    setFlag(FLAG_Z)
    flags_before = special["FLAGS"]

    testResult("NOP: executes", runInstruction(OP_NOP) is True)
    testResult("NOP: registers untouched",
               registers[0] == 0x1111 and registers[14] == 0x2222)
    testResult("NOP: flags untouched", special["FLAGS"] == flags_before)

def testMOV():
    """
    Verify MOV copies the source into the destination.

    :return: None
    """
    registers[3] = 0x1234

    testResult("MOV: executes", runInstruction(OP_MOV, a=3, b=5) is True)
    testResult("MOV: destination updated", registers[5] == 0x1234)
    testResult("MOV: source preserved", registers[3] == 0x1234)
    testResult("MOV: flags untouched", special["FLAGS"] == 0)

def testSWAP():
    """
    Verify SWAP exchanges two registers.

    :return: None
    """
    registers[1] = 0xAAAA
    registers[2] = 0x5555

    testResult("SWAP: executes", runInstruction(OP_SWAP, a=1, b=2) is True)
    testResult("SWAP: values exchanged",
               registers[1] == 0x5555 and registers[2] == 0xAAAA)

def testADD():
    """
    Verify ADD result and flags.

    :return: None
    """
    registers[1] = 2
    registers[2] = 3

    testResult("ADD: executes", runInstruction(OP_ADD, a=1, b=2) is True)
    testResult("ADD: result in destination", registers[2] == 5)
    testResult("ADD: source preserved", registers[1] == 2)
    testResult("ADD: Z clear on nonzero", not isFlagSet(FLAG_Z))
    testResult("ADD: N clear on positive", not isFlagSet(FLAG_N))

def testRegisterValidation():
    """
    Verify validRegister accepts only 0 .. REGISTER_COUNT - 1.

    :return: None
    """
    testResult("regval: 0 valid", validRegister(0))
    testResult("regval: last register valid",
               validRegister(REGISTER_COUNT - 1))
    testResult("regval: REGISTER_COUNT invalid",
               not validRegister(REGISTER_COUNT))
    testResult("regval: 15 invalid (4-bit field maximum)",
               not validRegister(15))
    testResult("regval: negative invalid", not validRegister(-1))
    testResult("regval: string invalid", not validRegister("1"))
    testResult("regval: None invalid", not validRegister(None))
    testResult("regval: float invalid", not validRegister(1.0))

def testFlagHelpers():
    """
    Verify setFlag, clearFlag, isFlagSet and clearFlags.

    :return: None
    """
    clearFlags()
    testResult("flags: all clear after clearFlags", special["FLAGS"] == 0)

    for flag in (FLAG_C, FLAG_Z, FLAG_N, FLAG_V,
                 FLAG_IF, FLAG_TF, FLAG_Q):
        clearFlags()
        setFlag(flag)
        testResult(f"flags: bit {flag} set",
                   isFlagSet(flag) and special["FLAGS"] == (1 << flag))
        clearFlag(flag)
        testResult(f"flags: bit {flag} cleared", not isFlagSet(flag))

    clearFlags()
    setFlag(FLAG_C)
    setFlag(FLAG_N)
    clearFlag(FLAG_C)
    testResult("flags: clearFlag leaves other bits alone",
               isFlagSet(FLAG_N) and not isFlagSet(FLAG_C))

    clearFlags()
    setFlag(FLAG_Z)
    setFlag(FLAG_Z)
    testResult("flags: setFlag is idempotent",
               special["FLAGS"] == (1 << FLAG_Z))

def testUpdateZNFlags():
    """
    Verify Zero and Negative flag computation.

    :return: None
    """
    clearFlags()
    updateZNFlags(0)
    testResult("ZN: zero sets Z, clears N",
               isFlagSet(FLAG_Z) and not isFlagSet(FLAG_N))

    updateZNFlags(0x8000)
    testResult("ZN: 0x8000 sets N, clears Z",
               isFlagSet(FLAG_N) and not isFlagSet(FLAG_Z))

    updateZNFlags(0x0001)
    testResult("ZN: 0x0001 clears both",
               not isFlagSet(FLAG_N) and not isFlagSet(FLAG_Z))

    updateZNFlags(0x10000)
    testResult("ZN: 0x10000 masks to zero",
               isFlagSet(FLAG_Z) and not isFlagSet(FLAG_N))

    updateZNFlags(0xFFFF)
    testResult("ZN: 0xFFFF sets N",
               isFlagSet(FLAG_N) and not isFlagSet(FLAG_Z))

    clearFlags()
    setFlag(FLAG_C)
    updateZNFlags(0)
    testResult("ZN: other flags preserved", isFlagSet(FLAG_C))

def testSUB():
    """
    Verify SUB computes destination - source.

    :return: None
    """
    registers[1] = 3
    registers[2] = 5

    testResult("SUB: executes", runInstruction(OP_SUB, a=1, b=2) is True)
    testResult("SUB: dst = dst - src", registers[2] == 2)
    testResult("SUB: source preserved", registers[1] == 3)
    testResult("SUB: Z clear", not isFlagSet(FLAG_Z))

    registers[1] = 7
    registers[2] = 7
    runInstruction(OP_SUB, a=1, b=2)
    testResult("SUB: equal operands give 0 and set Z",
               registers[2] == 0 and isFlagSet(FLAG_Z))

def testINC():
    """
    Verify INC increments field B.

    :return: None
    """
    registers[4] = 9

    testResult("INC: executes", runInstruction(OP_INC, b=4) is True)
    testResult("INC: incremented", registers[4] == 10)
    testResult("INC: flags clear", not isFlagSet(FLAG_Z))

def testDEC():
    """
    Verify DEC decrements field B.

    :return: None
    """
    registers[4] = 9

    testResult("DEC: executes", runInstruction(OP_DEC, b=4) is True)
    testResult("DEC: decremented", registers[4] == 8)

    registers[4] = 1
    runInstruction(OP_DEC, b=4)
    testResult("DEC: reaching zero sets Z",
               registers[4] == 0 and isFlagSet(FLAG_Z))

def testCMP():
    """
    Verify CMP sets flags from dst - src without modifying registers.

    :return: None
    """
    registers[1] = 5
    registers[2] = 5

    testResult("CMP: executes", runInstruction(OP_CMP, a=1, b=2) is True)
    testResult("CMP: equal sets Z", isFlagSet(FLAG_Z))
    testResult("CMP: equal clears N", not isFlagSet(FLAG_N))
    testResult("CMP: operands preserved",
               registers[1] == 5 and registers[2] == 5)

    registers[2] = 9
    runInstruction(OP_CMP, a=1, b=2)
    testResult("CMP: greater clears Z and N",
               not isFlagSet(FLAG_Z) and not isFlagSet(FLAG_N))
    testResult("CMP: destination preserved", registers[2] == 9)

def testCMPNegative():
    """
    Verify CMP sets N when dst < src (unsigned wraparound).

    :return: None
    """
    registers[1] = 5
    registers[2] = 3

    runInstruction(OP_CMP, a=1, b=2)
    testResult("CMP-: less sets N", isFlagSet(FLAG_N))
    testResult("CMP-: less clears Z", not isFlagSet(FLAG_Z))
    testResult("CMP-: operands preserved",
               registers[1] == 5 and registers[2] == 3)

def testAND():
    """
    Verify bitwise AND.

    :return: None
    """
    registers[1] = 0xFF0F
    registers[2] = 0x0FFF

    testResult("AND: executes", runInstruction(OP_AND, a=1, b=2) is True)
    testResult("AND: result", registers[2] == 0x0F0F)
    testResult("AND: source preserved", registers[1] == 0xFF0F)

def testOR():
    """
    Verify bitwise OR.

    :return: None
    """
    registers[1] = 0xF000
    registers[2] = 0x000F

    testResult("OR: executes", runInstruction(OP_OR, a=1, b=2) is True)
    testResult("OR: result", registers[2] == 0xF00F)
    testResult("OR: source preserved", registers[1] == 0xF000)

def testXOR():
    """
    Verify bitwise XOR.

    :return: None
    """
    registers[1] = 0xFFFF
    registers[2] = 0x0F0F

    testResult("XOR: executes", runInstruction(OP_XOR, a=1, b=2) is True)
    testResult("XOR: result", registers[2] == 0xF0F0)
    testResult("XOR: source preserved", registers[1] == 0xFFFF)

def testNOT():
    """
    Verify bitwise NOT.

    :return: None
    """
    registers[6] = 0x00FF

    testResult("NOT: executes", runInstruction(OP_NOT, b=6) is True)
    testResult("NOT: result masked to 16 bits", registers[6] == 0xFF00)

def testLogicFlags():
    """
    Verify logic instructions update Z and N.

    :return: None
    """
    registers[1] = 0xF0F0
    registers[2] = 0x0F0F
    runInstruction(OP_AND, a=1, b=2)
    testResult("logicflags: AND to zero sets Z",
               registers[2] == 0 and isFlagSet(FLAG_Z))

    registers[1] = 0x8000
    registers[2] = 0x0001
    runInstruction(OP_OR, a=1, b=2)
    testResult("logicflags: OR with MSB sets N, clears Z",
               isFlagSet(FLAG_N) and not isFlagSet(FLAG_Z))

    registers[1] = 0x1234
    registers[2] = 0x1234
    runInstruction(OP_XOR, a=1, b=2)
    testResult("logicflags: XOR equal sets Z, clears N",
               isFlagSet(FLAG_Z) and not isFlagSet(FLAG_N))

    registers[3] = 0x7FFF
    runInstruction(OP_NOT, b=3)
    testResult("logicflags: NOT 0x7FFF sets N",
               registers[3] == 0x8000 and isFlagSet(FLAG_N))

# =============================================================
#   EDGE CASE TESTS
# =============================================================

def testInvalidMOVRegisters():
    """
    Verify MOV rejects out-of-range registers without side effects.

    :return: None
    """
    registers[0] = 0x1234
    snapshot = list(registers)

    testResult("badMOV: invalid source rejected",
               runInstruction(OP_MOV, a=15, b=0) is False)
    testResult("badMOV: invalid destination rejected",
               runInstruction(OP_MOV, a=0, b=15) is False)
    testResult("badMOV: registers unchanged", registers == snapshot)

def testInvalidOpcode():
    """
    Verify unimplemented or out-of-family opcodes fail cleanly.

    :return: None
    """
    registers[1] = 0x1111
    snapshot = list(registers)
    flags = special["FLAGS"]

    for name, opcode in (("MUL (unimplemented)", OP_MUL),
                         ("opcode 0x1B (unassigned ALU)", 0x1B),
                         ("MEMORY family", 0x28),
                         ("CONTROL family", 0x30),
                         ("EXTENDED family", 0x7F)):
        testResult(f"badop: {name} returns False",
                   runInstruction(opcode, a=1, b=2) is False)

    testResult("badop: registers unchanged", registers == snapshot)
    testResult("badop: flags unchanged", special["FLAGS"] == flags)

def testADDOverflow():
    """
    Verify ADD wraps at 16 bits and updates Z/N accordingly.

    :return: None
    """
    registers[1] = 1
    registers[2] = 0xFFFF
    runInstruction(OP_ADD, a=1, b=2)
    testResult("ADDovf: 0xFFFF + 1 wraps to 0", registers[2] == 0)
    testResult("ADDovf: wrap to zero sets Z", isFlagSet(FLAG_Z))

    registers[1] = 1
    registers[2] = 0x7FFF
    runInstruction(OP_ADD, a=1, b=2)
    testResult("ADDovf: 0x7FFF + 1 = 0x8000", registers[2] == 0x8000)
    testResult("ADDovf: MSB result sets N", isFlagSet(FLAG_N))

    registers[1] = 0xFFFF
    registers[2] = 0xFFFF
    runInstruction(OP_ADD, a=1, b=2)
    testResult("ADDovf: 0xFFFF + 0xFFFF = 0xFFFE", registers[2] == 0xFFFE)

def testSUBUnderflow():
    """
    Verify SUB wraps below zero and sets N.

    :return: None
    """
    registers[1] = 1
    registers[2] = 0
    runInstruction(OP_SUB, a=1, b=2)
    testResult("SUBunf: 0 - 1 wraps to 0xFFFF", registers[2] == 0xFFFF)
    testResult("SUBunf: wrap sets N", isFlagSet(FLAG_N))
    testResult("SUBunf: wrap clears Z", not isFlagSet(FLAG_Z))

    registers[1] = 0xFFFF
    registers[2] = 0
    runInstruction(OP_SUB, a=1, b=2)
    testResult("SUBunf: 0 - 0xFFFF = 1", registers[2] == 1)

def testINCOverflow():
    """
    Verify INC wraps 0xFFFF to 0 and sets Z.

    :return: None
    """
    registers[0] = 0xFFFF
    runInstruction(OP_INC, b=0)
    testResult("INCovf: 0xFFFF wraps to 0", registers[0] == 0)
    testResult("INCovf: wrap sets Z", isFlagSet(FLAG_Z))

    registers[0] = 0x7FFF
    runInstruction(OP_INC, b=0)
    testResult("INCovf: 0x7FFF -> 0x8000 sets N",
               registers[0] == 0x8000 and isFlagSet(FLAG_N))

def testDECUnderflow():
    """
    Verify DEC wraps 0 to 0xFFFF and sets N.

    :return: None
    """
    registers[0] = 0
    runInstruction(OP_DEC, b=0)
    testResult("DECunf: 0 wraps to 0xFFFF", registers[0] == 0xFFFF)
    testResult("DECunf: wrap sets N", isFlagSet(FLAG_N))
    testResult("DECunf: wrap clears Z", not isFlagSet(FLAG_Z))

def testMOVSelf():
    """
    Verify MOV Rn, Rn is a no-op.

    :return: None
    """
    registers[7] = 0xBEEF

    testResult("MOVself: executes", runInstruction(OP_MOV, a=7, b=7) is True)
    testResult("MOVself: value unchanged", registers[7] == 0xBEEF)

def testSWAPSelf():
    """
    Verify SWAP Rn, Rn is a no-op.

    :return: None
    """
    registers[7] = 0xBEEF

    testResult("SWAPself: executes",
               runInstruction(OP_SWAP, a=7, b=7) is True)
    testResult("SWAPself: value unchanged", registers[7] == 0xBEEF)

def testLogicZeroResult():
    """
    Verify zero-producing logic operations set Z.

    :return: None
    """
    registers[1] = 0xABCD
    runInstruction(OP_XOR, a=1, b=1)
    testResult("logic0: XOR Rn,Rn clears register and sets Z",
               registers[1] == 0 and isFlagSet(FLAG_Z))

    registers[1] = 0xFFFF
    registers[2] = 0
    runInstruction(OP_AND, a=1, b=2)
    testResult("logic0: AND with 0 gives 0 and sets Z",
               registers[2] == 0 and isFlagSet(FLAG_Z))

    registers[1] = 0
    registers[2] = 0
    runInstruction(OP_OR, a=1, b=2)
    testResult("logic0: OR of zeros gives 0 and sets Z",
               registers[2] == 0 and isFlagSet(FLAG_Z))

def testNOTEdgeCases():
    """
    Verify NOT at the extremes and its involution property.

    :return: None
    """
    registers[0] = 0x0000
    runInstruction(OP_NOT, b=0)
    testResult("NOTedge: NOT 0 = 0xFFFF", registers[0] == 0xFFFF)
    testResult("NOTedge: result sets N", isFlagSet(FLAG_N))

    runInstruction(OP_NOT, b=0)
    testResult("NOTedge: NOT 0xFFFF = 0", registers[0] == 0)
    testResult("NOTedge: result sets Z", isFlagSet(FLAG_Z))

    registers[0] = 0xAAAA
    runInstruction(OP_NOT, b=0)
    runInstruction(OP_NOT, b=0)
    testResult("NOTedge: double NOT restores value", registers[0] == 0xAAAA)

def testMalformedDecodedObjects():
    """
    Verify executors reject decoded objects with bad operand fields.

    :return: None
    """
    snapshot = list(registers)

    def make(opcode, a, b):
        return {"opcode": opcode, "size": 0, "fieldA": a, "fieldB": b,
                "family": FMT_ALU}

    cases = [
        ("MOV fieldA None",   make(OP_MOV, None, 2)),
        ("MOV fieldB None",   make(OP_MOV, 1, None)),
        ("MOV fieldA string", make(OP_MOV, "x", 2)),
        ("MOV fieldA 16",     make(OP_MOV, 16, 2)),
        ("MOV fieldB -1",     make(OP_MOV, 1, -1)),
        ("ADD fieldA float",  make(OP_ADD, 1.5, 2)),
        ("INC fieldB None",   make(OP_INC, 0, None)),
        ("NOT fieldB string", make(OP_NOT, 0, "x")),
        ("DEC fieldB 99",     make(OP_DEC, 0, 99)),
    ]
    for name, decoded in cases:
        testResult(f"malformed: {name} rejected",
                   executeInstruction(decoded) is False)

    testResult("malformed: registers unchanged", registers == snapshot)
    testResult("malformed: getSrcDst None on bad field",
               getSrcDst(make(OP_MOV, None, 1)) is None)

def testInstructionDecodeExtremes():
    """
    Verify decoding of boundary instruction words.

    :return: None
    """
    testResult("extremes: 0x0000 -> NOP fields",
               decodeFields(0x0000) == (0, 0, 0, 0))
    testResult("extremes: 0xFFFF -> all ones",
               decodeFields(0xFFFF) == (0x7F, 1, 0xF, 0xF))
    testResult("extremes: 0x8000 -> top opcode bit only",
               decodeFields(0x8000) == (0x40, 0, 0, 0))
    testResult("extremes: 0x0100 -> size bit only",
               decodeFields(0x0100) == (0, 1, 0, 0))
    testResult("extremes: 0x00F0 -> field A only",
               decodeFields(0x00F0) == (0, 0, 0xF, 0))
    testResult("extremes: 0x000F -> field B only",
               decodeFields(0x000F) == (0, 0, 0, 0xF))
    testResult("extremes: 0xFFFF family is EXTENDED",
               decodeInstruction(0xFFFF)["family"] == FMT_EXTENDED)

    roundtrip = all(
        decodeFields(encodeInstruction(op, sz, a, b)) == (op, sz, a, b)
        for op in (0x00, 0x1C, 0x7F)
        for sz in (0, 1)
        for a in (0x0, 0xF)
        for b in (0x0, 0xF)
    )
    testResult("extremes: encode/decode round-trip", roundtrip)

def testMultiStepExecution():
    """
    Verify a short program runs correctly across several cpuStep calls.

    :return: None
    """
    resetCPU()

    loadProgram([
        encodeInstruction(OP_NOP),
        encodeInstruction(OP_MOV, 0, 1, 2),     # R2 = R1
        encodeInstruction(OP_INC, 0, 0, 2),     # R2 += 1
        encodeInstruction(OP_ADD, 0, 1, 2),     # R2 += R1
    ])
    registers[1] = 5

    start = special["PC"]
    testResult("multistep: PC starts at reset ISR", start == 0xF100)

    cpuStep()
    testResult("multistep: NOP leaves R2 at 0", registers[2] == 0)
    testResult("multistep: PC advances by 2", special["PC"] == start + 2)

    cpuStep()
    testResult("multistep: MOV R1->R2", registers[2] == 5)

    cpuStep()
    testResult("multistep: INC R2", registers[2] == 6)

    cpuStep()
    testResult("multistep: ADD R1 into R2", registers[2] == 11)
    testResult("multistep: PC after four steps", special["PC"] == start + 8)
    testResult("multistep: IP holds last instruction address",
               special["IP"] == start + 6)

def testMemoryBoundaries():
    """
    Verify access succeeds or fails correctly at every region edge.

    :return: None
    """
    testResult("bounds: 0x5BFF (reserved) write rejected",
               writeByte(0x5BFF, 0x11) is False)
    testResult("bounds: 0x5C00 (RAM start) write ok",
               writeByte(0x5C00, 0x11) is True)
    testResult("bounds: 0xDBFF (RAM end) write ok",
               writeByte(0xDBFF, 0x22) is True)
    testResult("bounds: 0xDC00 (MMIO start) write ok",
               writeByte(0xDC00, 0x33) is True)
    testResult("bounds: 0xDFFF (MMIO end) write ok",
               writeByte(0xDFFF, 0x44) is True)
    testResult("bounds: 0xE000 (USR start) write ok",
               writeByte(0xE000, 0x55) is True)
    testResult("bounds: 0xEFFF (USR end) write ok",
               writeByte(0xEFFF, 0x66) is True)
    testResult("bounds: 0xF000 (ROM start) write rejected",
               writeByte(0xF000, 0x77) is False)
    testResult("bounds: 0xFFFF (ROM end) write rejected",
               writeByte(0xFFFF, 0x88) is False)
    testResult("bounds: 0x10000 write rejected",
               writeByte(0x10000, 0x99) is False)

    testResult("bounds: edge bytes read back",
               readByte(0x5C00) == 0x11 and readByte(0xDBFF) == 0x22
               and readByte(0xDC00) == 0x33 and readByte(0xDFFF) == 0x44
               and readByte(0xE000) == 0x55 and readByte(0xEFFF) == 0x66)

def testMemoryTransitions():
    """
    Verify adjacent bytes across region seams land in different devices.

    :return: None
    """
    writeByte(0xDBFF, 0xAA)
    writeByte(0xDC00, 0xBB)
    testResult("trans: RAM->MMIO seam isolated",
               RAM[-1] == 0xAA and MMIO[0] == 0xBB)

    writeByte(0xDFFF, 0xCC)
    writeByte(0xE000, 0xDD)
    testResult("trans: MMIO->USR seam isolated",
               MMIO[-1] == 0xCC and USR[0] == 0xDD)

    writeByte(0xEFFF, 0xEE)
    testResult("trans: USR end stored in USR", USR[-1] == 0xEE)
    testResult("trans: ROM start unaffected", ROM[0] == 0x00)

    writeByte(0x5C00, 0xFF)
    testResult("trans: RESERVED->RAM seam isolated",
               RAM[0] == 0xFF and readByte(0x5BFF) == 0x00)

def testBoundaryWordReads():
    """
    Verify word reads that cross a device seam are rejected.

    :return: None
    """
    seams = [
        (0x5BFF, "RESERVED->RAM"),
        (0xDBFF, "RAM->MMIO"),
        (0xDFFF, "MMIO->USR"),
        (0xEFFF, "USR->ROM"),
        (0xFFFF, "ROM->unmapped"),
    ]
    for addr, name in seams:
        testResult(f"wordread: {name} seam rejected",
                   readWord(addr) is None)

    writeWord(0xDBFE, 0xCAFE)
    testResult("wordread: last in-RAM word readable",
               readWord(0xDBFE) == 0xCAFE)
    testResult("wordread: first in-RAM word readable",
               readWord(0x5C00) == 0x0000)
    testResult("wordread: last in-ROM word readable",
               readWord(0xFFFE) == 0x0000)

def testBoundaryWordWrites():
    """
    Verify word writes that cross a device seam are rejected atomically.

    :return: None
    """
    seams = [
        (0x5BFF, "RESERVED->RAM"),
        (0xDBFF, "RAM->MMIO"),
        (0xDFFF, "MMIO->USR"),
        (0xEFFF, "USR->ROM"),
        (0xFFFF, "ROM->unmapped"),
    ]
    for addr, name in seams:
        testResult(f"wordwrite: {name} seam rejected",
                   writeWord(addr, 0xFFFF) is False)

    testResult("wordwrite: rejected writes leave RAM end untouched",
               RAM[-1] == 0x00)
    testResult("wordwrite: rejected writes leave MMIO untouched",
               MMIO[0] == 0x00 and MMIO[-1] == 0x00)
    testResult("wordwrite: rejected writes leave USR untouched",
               USR[0] == 0x00 and USR[-1] == 0x00)

    testResult("wordwrite: last in-RAM word writable",
               writeWord(0xDBFE, 0x1234) is True)
    testResult("wordwrite: last in-USR word writable",
               writeWord(0xEFFE, 0x5678) is True)

def testROMWriteProtection():
    """
    Verify ROM cannot be modified through any write path.

    :return: None
    """
    testResult("rom: writeByte rejected", writeByte(0xF200, 0xAA) is False)
    testResult("rom: writeWord rejected", writeWord(0xF200, 0xAAAA) is False)
    testResult("rom: contents unchanged after rejected writes",
               ROM[0x200] == 0x00 and ROM[0x201] == 0x00)

    testResult("rom: boot ROM first byte protected",
               writeByte(0xF000, 0xAA) is False and ROM[0] == 0x00)
    testResult("rom: boot ROM last byte protected",
               writeByte(0xFFFF, 0xAA) is False and ROM[-1] == 0x00)

    resetCPU()
    reset_isr = readWord(calcSIVTAddr(SYS_RESET))
    writeWord(calcSIVTAddr(SYS_RESET), 0x0000)
    testResult("rom: IVT cannot be overwritten at run time",
               readWord(calcSIVTAddr(SYS_RESET)) == reset_isr)

def testRAMBoundaries():
    """
    Verify RAM size, first/last bytes and in-range word access.

    :return: None
    """
    testResult("ram: backing store is 32KB", len(RAM) == 32 * 1024)

    writeByte(0x5C00, 0x01)
    writeByte(0xDBFF, 0x02)
    testResult("ram: first byte maps to index 0", RAM[0] == 0x01)
    testResult("ram: last byte maps to final index", RAM[-1] == 0x02)

    writeWord(0x5C00, 0xA1B2)
    testResult("ram: word at first address", readWord(0x5C00) == 0xA1B2)
    writeWord(0xDBFE, 0xC3D4)
    testResult("ram: word ending at last address",
               readWord(0xDBFE) == 0xC3D4)
    testResult("ram: word straddling end rejected",
               readWord(0xDBFF) is None)

def testMMIOBoundaries():
    """
    Verify MMIO size, first/last bytes and in-range word access.

    :return: None
    """
    testResult("mmio: backing store is 1KB", len(MMIO) == 1024)

    writeByte(0xDC00, 0x01)
    writeByte(0xDFFF, 0x02)
    testResult("mmio: first byte maps to index 0", MMIO[0] == 0x01)
    testResult("mmio: last byte maps to final index", MMIO[-1] == 0x02)

    writeWord(0xDC00, 0xA1B2)
    testResult("mmio: word at first address", readWord(0xDC00) == 0xA1B2)
    writeWord(0xDFFE, 0xC3D4)
    testResult("mmio: word ending at last address",
               readWord(0xDFFE) == 0xC3D4)
    testResult("mmio: word straddling end rejected",
               readWord(0xDFFF) is None)

def testIVTBoundaries():
    """
    Verify every IVT entry and ISR address lies in the right region.

    :return: None
    """
    resetCPU()

    sivt_ok = all(
        getMemRegionData(calcSIVTAddr(v), 2) is not None
        and getMemRegionData(calcSIVTAddr(v), 2)[0] == "ROM"
        for v in SYSTEM_ISR_ADDRS
    )
    testResult("ivtbounds: all SIVT entries inside ROM", sivt_ok)

    uivt_ok = all(
        getMemRegionData(calcUIVTAddr(v), 2) is not None
        and getMemRegionData(calcUIVTAddr(v), 2)[0] == "USR"
        for v in USER_ISR_ADDRS
    )
    testResult("ivtbounds: all UIVT entries inside USR", uivt_ok)

    sys_isr_ok = all(
        getMemArea(a) is not None and getMemArea(a)[0] == "ROM"
        for a in SYSTEM_ISR_ADDRS.values()
    )
    testResult("ivtbounds: all system ISRs inside ROM", sys_isr_ok)

    usr_isr_ok = all(
        getMemArea(a) is not None and getMemArea(a)[0] == "USR"
        for a in USER_ISR_ADDRS.values()
    )
    testResult("ivtbounds: all user ISRs inside USR", usr_isr_ok)

    aligned = all(
        a % 2 == 0
        for a in list(SYSTEM_ISR_ADDRS.values())
        + list(USER_ISR_ADDRS.values())
    )
    testResult("ivtbounds: ISR addresses are word aligned", aligned)

    last_sys = max(calcSIVTAddr(v) for v in SYSTEM_ISR_ADDRS) + 1
    testResult("ivtbounds: SIVT does not overlap first ISR",
               last_sys < min(SYSTEM_ISR_ADDRS.values()))

    last_usr = max(calcUIVTAddr(v) for v in USER_ISR_ADDRS) + 1
    testResult("ivtbounds: UIVT does not overlap first user ISR",
               last_usr < min(USER_ISR_ADDRS.values()))

    unique = len(set(SYSTEM_ISR_ADDRS.values())) == len(SYSTEM_ISR_ADDRS)
    testResult("ivtbounds: system ISR addresses are unique", unique)

def testPipeline():
    """
    Verify the fetch, decode and execute stages behave independently
    and that cpuStep composes them (the core is non-pipelined for now).

    :return: None
    """
    resetCPU()

    word = encodeInstruction(OP_MOV, 0, 1, 2)
    loadProgram([word, word])
    registers[1] = 7

    fetched = fetchInstruction()
    testResult("pipeline: fetch returns instruction word", fetched == word)
    testResult("pipeline: fetch latches IP", special["IP"] == 0xF100)
    testResult("pipeline: fetch advances PC", special["PC"] == 0xF102)
    testResult("pipeline: fetch has no execute side effects",
               registers[2] == 0)

    decoded = decodeInstruction(fetched)
    testResult("pipeline: decode has no execute side effects",
               registers[2] == 0)
    testResult("pipeline: decode fields correct",
               decoded["opcode"] == OP_MOV and decoded["fieldA"] == 1
               and decoded["fieldB"] == 2)

    testResult("pipeline: execute reports success",
               executeInstruction(decoded) is True)
    testResult("pipeline: execute performs the operation", registers[2] == 7)

    registers[2] = 0
    cpuStep()
    testResult("pipeline: cpuStep composes the three stages",
               registers[2] == 7 and special["PC"] == 0xF104)

# =============================================================
#   TEST ORCHESTRATOR
# =============================================================

#: Ordered list of every test function run by :func:`runAllTests`.
ALL_TESTS = [

    # Core
    testMemoryMap,
    testMemoryReadWrite,
    testWordAccess,
    testStackOperations,
    testVectorHelpers,
    testIVTInitialization,
    testCPUReset,
    testInstructionDecoder,

    # Instructions
    testNOP,
    testMOV,
    testSWAP,
    testADD,
    testRegisterValidation,
    testFlagHelpers,
    testUpdateZNFlags,
    testSUB,
    testINC,
    testDEC,
    testCMP,
    testCMPNegative,
    testAND,
    testOR,
    testXOR,
    testNOT,
    testLogicFlags,

    # Edge cases
    testInvalidMOVRegisters,
    testInvalidOpcode,
    testADDOverflow,
    testSUBUnderflow,
    testINCOverflow,
    testDECUnderflow,
    testMOVSelf,
    testSWAPSelf,
    testLogicZeroResult,
    testNOTEdgeCases,
    testMalformedDecodedObjects,
    testInstructionDecodeExtremes,
    testMultiStepExecution,
    testMemoryBoundaries,
    testMemoryTransitions,
    testBoundaryWordReads,
    testBoundaryWordWrites,
    testROMWriteProtection,
    testRAMBoundaries,
    testMMIOBoundaries,
    testIVTBoundaries,
    testPipeline,

]

def runAllTests():
    """
    Run the complete test suite with one call.

    Resets the counters, then for every function in :data:`ALL_TESTS`
    performs a full :func:`resetMachine` (so tests are order-independent),
    runs it, and records an exception as a failure instead of aborting.
    Prints a summary at the end.

    :return: ``True`` if every check passed, ``False`` otherwise.
    :rtype: bool
    """
    global tests_passed
    global tests_failed

    tests_passed = 0
    tests_failed = 0

    for test in ALL_TESTS:
        print(f"\n--- {test.__name__} ---")

        resetMachine()

        try:
            test()
        except Exception as exc:
            testResult(
                f"{test.__name__} raised {type(exc).__name__}: {exc}",
                False
            )

    printTestSummary()

    return tests_failed == 0

# =============================================================
#   MAIN
# =============================================================
if __name__ == "__main__" :
    sys.exit(0 if runAllTests() else 1)