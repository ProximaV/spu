#include "ins.hpp"

// Exact canonical feature flags per SPU ISA v1.2 (27 Jan 2007).
// Unlike factory spu.py:
//   - Only the 11 true read-modify-write instructions (addx, sfx, cgx, bgx,
//     mpyhha, mpyhhau, dfma, dfms, dfnms, dfnma, iohl) have CF_USE1|CF_CHG1.
//   - Store instructions (stqd, stqa, stqr) have CF_USE1|CF_CHG2 (emitting dr_W).
//   - stqx has CF_USE1|CF_USE2|CF_USE3 (never mutates RT).
//   - bisl / bisled have CF_CHG1|CF_USE2|CF_CALL (recognized by IDA call graph).
//   - stopd has CF_STOP.
//   - False-target halt instructions (heq*, hgt*, hlgt*) & fscrwr do NOT set CF_CHG1.
//   - RI7 / RI10 instructions include CF_USE3.

const instruc_t Instructions[] =
{
    { "",           0 },                                                    // SPU_null

    // --- Memory: Load / Store & Generate Controls ---
    { "lqd",        CF_CHG1 | CF_USE2 },                                    // Load Quadword (d-form)
    { "lqx",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Load Quadword (x-form)
    { "lqa",        CF_CHG1 | CF_USE2 },                                    // Load Quadword (a-form)
    { "lqr",        CF_CHG1 | CF_USE2 },                                    // Load Quadword Instruction Relative (a-form)
    { "stqd",       CF_USE1 | CF_CHG2 },                                    // Store Quadword (d-form)
    { "stqx",       CF_USE1 | CF_USE2 | CF_USE3 },                          // Store Quadword (x-form)
    { "stqa",       CF_USE1 | CF_CHG2 },                                    // Store Quadword (a-form)
    { "stqr",       CF_USE1 | CF_CHG2 },                                    // Store Quadword Instruction Relative (a-form)
    { "cbd",        CF_CHG1 | CF_USE2 },                                    // Generate Controls for Byte Insertion (d-form)
    { "cbx",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Generate Controls for Byte Insertion (x-form)
    { "chd",        CF_CHG1 | CF_USE2 },                                    // Generate Controls for Halfword Insertion (d-form)
    { "chx",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Generate Controls for Halfword Insertion (x-form)
    { "cwd",        CF_CHG1 | CF_USE2 },                                    // Generate Controls for Word Insertion (d-form)
    { "cwx",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Generate Controls for Word Insertion (x-form)
    { "cdd",        CF_CHG1 | CF_USE2 },                                    // Generate Controls for Doubleword Insertion (d-form)
    { "cdx",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Generate Controls for Doubleword Insertion (x-form)

    // --- Constant Formation ---
    { "ilh",        CF_CHG1 | CF_USE2 },                                    // Immediate Load Halfword
    { "ilhu",       CF_CHG1 | CF_USE2 },                                    // Immediate Load Halfword Upper
    { "il",         CF_CHG1 | CF_USE2 },                                    // Immediate Load Word
    { "ila",        CF_CHG1 | CF_USE2 },                                    // Immediate Load Address
    { "iohl",       CF_USE1 | CF_CHG1 | CF_USE2 },                          // Immediate Or Halfword Lower (reads & modifies RT)
    { "fsmbi",      CF_CHG1 | CF_USE2 },                                    // Form Select Mask for Bytes Immediate

    // --- Integer & Logical ---
    { "ah",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Add Halfword
    { "ahi",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Add Halfword Immediate
    { "a",          CF_CHG1 | CF_USE2 | CF_USE3 },                          // Add Word
    { "ai",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Add Word Immediate
    { "sfh",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Subtract from Halfword
    { "sfhi",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Subtract from Halfword Immediate
    { "sf",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Subtract from Word
    { "sfi",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Subtract from Word Immediate
    { "addx",       CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Add Extended (reads RT carry)
    { "cg",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Carry Generate
    { "cgx",        CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Carry Generate Extended (reads RT carry)
    { "sfx",        CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Subtract from Extended (reads RT borrow)
    { "bg",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Borrow Generate
    { "bgx",        CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Borrow Generate Extended (reads RT borrow)
    { "mpy",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply
    { "mpyu",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply Unsigned
    { "mpyi",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply Immediate
    { "mpyui",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply Unsigned Immediate
    { "mpyh",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply High
    { "mpys",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply and Shift Right
    { "mpyhh",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply High High
    { "mpyhha",     CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Multiply High High and Add (reads RT)
    { "mpyhhu",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Multiply High High Unsigned
    { "mpyhhau",    CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Multiply High High Unsigned and Add (reads RT)
    { "clz",        CF_CHG1 | CF_USE2 },                                    // Count Leading Zeros
    { "cntb",       CF_CHG1 | CF_USE2 },                                    // Count Ones in Bytes
    { "fsmb",       CF_CHG1 | CF_USE2 },                                    // Form Select Mask for Bytes
    { "fsmh",       CF_CHG1 | CF_USE2 },                                    // Form Select Mask for Halfwords
    { "fsm",        CF_CHG1 | CF_USE2 },                                    // Form Select Mask for Words
    { "gbb",        CF_CHG1 | CF_USE2 },                                    // Gather Bits from Bytes
    { "gbh",        CF_CHG1 | CF_USE2 },                                    // Gather Bits from Halfwords
    { "gb",         CF_CHG1 | CF_USE2 },                                    // Gather Bits from Words
    { "avgb",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Average Bytes
    { "absdb",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Absolute Differences of Bytes
    { "sumb",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Sum Bytes into Halfwords
    { "xsbh",       CF_CHG1 | CF_USE2 },                                    // Extend Sign Byte to Halfword
    { "xshw",       CF_CHG1 | CF_USE2 },                                    // Extend Sign Halfword to Word
    { "xswd",       CF_CHG1 | CF_USE2 },                                    // Extend Sign Word to Doubleword
    { "and",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // And
    { "andc",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // And with Complement
    { "andbi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // And Byte Immediate
    { "andhi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // And Halfword Immediate
    { "andi",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // And Word Immediate
    { "or",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Or
    { "orc",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Or with Complement
    { "orbi",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Or Byte Immediate
    { "orhi",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Or Halfword Immediate
    { "ori",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Or Word Immediate
    { "orx",        CF_CHG1 | CF_USE2 },                                    // Or Across
    { "xor",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Exclusive Or
    { "xorbi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Exclusive Or Byte Immediate
    { "xorhi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Exclusive Or Halfword Immediate
    { "xori",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Exclusive Or Word Immediate
    { "nand",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Nand
    { "nor",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Nor
    { "eqv",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Equivalent
    { "mpya",       CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },                // Multiply and Add
    { "selb",       CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },                // Select Bits
    { "shufb",      CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },                // Shuffle Bytes

    // --- Shift & Rotate ---
    { "shlh",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Halfword
    { "shlhi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Halfword Immediate (RI7!)
    { "shl",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Word
    { "shli",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Word Immediate
    { "shlqbi",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Quadword by Bits
    { "shlqbii",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Quadword by Bits Immediate
    { "shlqby",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Quadword by Bytes
    { "shlqbyi",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Quadword by Bytes Immediate
    { "shlqbybi",   CF_CHG1 | CF_USE2 | CF_USE3 },                          // Shift Left Quadword by Bytes from Bit Shift Count
    { "roth",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Halfword
    { "rothi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Halfword Immediate
    { "rot",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Word
    { "roti",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Word Immediate
    { "rotqby",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Quadword by Bytes
    { "rotqbyi",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Quadword by Bytes Immediate
    { "rotqbybi",   CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Quadword by Bytes from Bit Shift Count
    { "rotqbi",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Quadword by Bits
    { "rotqbii",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate Quadword by Bits Immediate
    { "rothm",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Halfword
    { "rothmi",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Halfword Immediate
    { "rotm",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Word
    { "rotmi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Word Immediate
    { "rotqmby",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Quadword by Bytes
    { "rotqmbyi",   CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Quadword by Bytes Immediate
    { "rotqmbybi",  CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Quadword Bytes from Bit Shift Count
    { "rotqmbi",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Quadword by Bits
    { "rotqmbii",   CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Quadword by Bits Immediate
    { "rotmah",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Algebraic Halfword
    { "rotmahi",    CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Algebraic Halfword Immediate
    { "rotma",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Algebraic Word
    { "rotmai",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Rotate and Mask Algebraic Word Immediate

    // --- Compare, Halt & Branch ---
    { "heq",        CF_USE1 | CF_USE2 },                                    // Halt If Equal (RT is false target, omitted)
    { "heqi",       CF_USE1 | CF_USE2 },                                    // Halt If Equal Immediate
    { "hgt",        CF_USE1 | CF_USE2 },                                    // Halt If Greater Than
    { "hgti",       CF_USE1 | CF_USE2 },                                    // Halt If Greater Than Immediate
    { "hlgt",       CF_USE1 | CF_USE2 },                                    // Halt If Logically Greater Than
    { "hlgti",      CF_USE1 | CF_USE2 },                                    // Halt If Logically Greater Than Immediate
    { "ceqb",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Equal Byte
    { "ceqbi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Equal Byte Immediate
    { "ceqh",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Equal Halfword
    { "ceqhi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Equal Halfword Immediate
    { "ceq",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Equal Word
    { "ceqi",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Equal Word Immediate
    { "cgtb",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Greater Than Byte
    { "cgtbi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Greater Than Byte Immediate
    { "cgth",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Greater Than Halfword
    { "cgthi",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Greater Than Halfword Immediate
    { "cgt",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Greater Than Word
    { "cgti",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Greater Than Word Immediate
    { "clgtb",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Logical Greater Than Byte
    { "clgtbi",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Logical Greater Than Byte Immediate
    { "clgth",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Logical Greater Than Halfword
    { "clgthi",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Logical Greater Than Halfword Immediate
    { "clgt",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Logical Greater Than Word
    { "clgti",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Compare Logical Greater Than Word Immediate
    { "br",         CF_USE1 | CF_STOP },                                    // Branch Relative
    { "bra",        CF_USE1 | CF_STOP },                                    // Branch Absolute
    { "brsl",       CF_CHG1 | CF_USE2 | CF_CALL },                          // Branch Relative and Set Link
    { "brasl",      CF_CHG1 | CF_USE2 | CF_CALL },                          // Branch Absolute and Set Link
    { "bi",         CF_USE1 | CF_STOP },                                    // Branch Indirect (CF_JUMP handled dynamically when RA != lr)
    { "iret",       CF_STOP },                                              // Interrupt Return (jumps to SRR0)
    { "bisled",     CF_CHG1 | CF_USE2 | CF_CALL },                          // Branch Indirect and Set Link if External Data
    { "bisl",       CF_CHG1 | CF_USE2 | CF_CALL },                          // Branch Indirect and Set Link
    { "brnz",       CF_USE1 | CF_USE2 },                                    // Branch If Not Zero Word
    { "brz",        CF_USE1 | CF_USE2 },                                    // Branch If Zero Word
    { "brhnz",      CF_USE1 | CF_USE2 },                                    // Branch If Not Zero Halfword
    { "brhz",       CF_USE1 | CF_USE2 },                                    // Branch If Zero Halfword
    { "biz",        CF_USE1 | CF_USE2 | CF_JUMP },                          // Branch Indirect If Zero
    { "binz",       CF_USE1 | CF_USE2 | CF_JUMP },                          // Branch Indirect If Not Zero
    { "bihz",       CF_USE1 | CF_USE2 | CF_JUMP },                          // Branch Indirect If Zero Halfword
    { "bihnz",      CF_USE1 | CF_USE2 | CF_JUMP },                          // Branch Indirect If Not Zero Halfword

    // --- Hint for Branch ---
    { "hbr",        0 },                                                    // Hint for Branch (r-form)
    { "hbra",       0 },                                                    // Hint for Branch (a-form)
    { "hbrr",       0 },                                                    // Hint for Branch Relative

    // --- Floating-Point ---
    { "fa",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Add
    { "dfa",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Add
    { "fs",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Subtract
    { "dfs",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Subtract
    { "fm",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Multiply
    { "dfm",        CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Multiply
    { "fma",        CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },                // Floating Multiply and Add
    { "dfma",       CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Double Floating Multiply and Add (reads RT)
    { "fnms",       CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },                // Floating Negative Multiply and Subtract
    { "dfnms",      CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Double Floating Negative Multiply and Subtract (reads RT)
    { "fms",        CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },                // Floating Multiply and Subtract
    { "dfms",       CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Double Floating Multiply and Subtract (reads RT)
    { "dfnma",      CF_USE1 | CF_CHG1 | CF_USE2 | CF_USE3 },                // Double Floating Negative Multiply and Add (reads RT)
    { "frest",      CF_CHG1 | CF_USE2 },                                    // Floating Reciprocal Estimate
    { "frsqest",    CF_CHG1 | CF_USE2 },                                    // Floating Reciprocal Absolute Square Root Estimate
    { "fi",         CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Interpolate
    { "csflt",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Convert Signed Integer to Floating
    { "cflts",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Convert Floating to Signed Integer
    { "cuflt",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Convert Unsigned Integer to Floating
    { "cfltu",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Convert Floating to Unsigned Integer
    { "frds",       CF_CHG1 | CF_USE2 },                                    // Floating Round Double to Single
    { "fesd",       CF_CHG1 | CF_USE2 },                                    // Floating Extend Single to Double
    { "dfceq",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Compare Equal
    { "dfcmeq",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Compare Magnitude Equal
    { "dfcgt",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Compare Greater Than
    { "dfcmgt",     CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Compare Magnitude Greater Than
    { "dftsv",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Double Floating Test Special Value
    { "fceq",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Compare Equal
    { "fcmeq",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Compare Magnitude Equal
    { "fcgt",       CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Compare Greater Than
    { "fcmgt",      CF_CHG1 | CF_USE2 | CF_USE3 },                          // Floating Compare Magnitude Greater Than
    { "fscrwr",     CF_USE1 },                                              // Floating-Point Status and Control Register Write (RT is false target)
    { "fscrrd",     CF_CHG1 },                                              // Floating-Point Status and Control Register Read

    // --- Control ---
    { "stop",       CF_USE1 | CF_STOP },                                    // Stop and Signal
    { "stopd",      CF_USE1 | CF_USE2 | CF_USE3 | CF_STOP },                // Stop and Signal with Dependencies
    { "lnop",       0 },                                                    // No Operation (Load)
    { "nop",        0 },                                                    // No Operation (Execute)
    { "sync",       0 },                                                    // Synchronize
    { "dsync",      0 },                                                    // Synchronize Data
    { "mfspr",      CF_CHG1 | CF_USE2 },                                    // Move from Special-Purpose Register
    { "mtspr",      CF_CHG1 | CF_USE2 },                                    // Move to Special-Purpose Register

    // --- Channel ---
    { "rdch",       CF_CHG1 | CF_USE2 },                                    // Read Channel
    { "rchcnt",     CF_CHG1 | CF_USE2 },                                    // Read Channel Count
    { "wrch",       CF_CHG1 | CF_USE2 },                                    // Write Channel

    // --- Simplified Mnemonics ---
    { "lr",         CF_CHG1 | CF_USE2 },                                    // Load Register (ori/shlqbyi rt, ra, 0)
};

static_assert(qnumber(Instructions) == SPU_last, "Instructions array must match spu_insn_t enum");

static const char *const kInsnComments[] =
{
    nullptr,                                                                // SPU_null
    "Load Quadword (d-form)",                                               // SPU_lqd
    "Load Quadword (x-form)",                                               // SPU_lqx
    "Load Quadword (a-form)",                                               // SPU_lqa
    "Load Quadword Instruction Relative (a-form)",                          // SPU_lqr
    "Store Quadword (d-form)",                                              // SPU_stqd
    "Store Quadword (x-form)",                                              // SPU_stqx
    "Store Quadword (a-form)",                                              // SPU_stqa
    "Store Quadword Instruction Relative (a-form)",                         // SPU_stqr
    "Generate Controls for Byte Insertion (d-form)",                        // SPU_cbd
    "Generate Controls for Byte Insertion (x-form)",                        // SPU_cbx
    "Generate Controls for Halfword Insertion (d-form)",                    // SPU_chd
    "Generate Controls for Halfword Insertion (x-form)",                    // SPU_chx
    "Generate Controls for Word Insertion (d-form)",                        // SPU_cwd
    "Generate Controls for Word Insertion (x-form)",                        // SPU_cwx
    "Generate Controls for Doubleword Insertion (d-form)",                  // SPU_cdd
    "Generate Controls for Doubleword Insertion (x-form)",                  // SPU_cdx

    "Immediate Load Halfword",                                              // SPU_ilh
    "Immediate Load Halfword Upper",                                        // SPU_ilhu
    "Immediate Load Word",                                                  // SPU_il
    "Immediate Load Address",                                               // SPU_ila
    "Immediate Or Halfword Lower",                                          // SPU_iohl
    "Form Select Mask for Bytes Immediate",                                 // SPU_fsmbi

    "Add Halfword",                                                         // SPU_ah
    "Add Halfword Immediate",                                               // SPU_ahi
    "Add Word",                                                             // SPU_a
    "Add Word Immediate",                                                   // SPU_ai
    "Subtract from Halfword",                                               // SPU_sfh
    "Subtract from Halfword Immediate",                                     // SPU_sfhi
    "Subtract from Word",                                                   // SPU_sf
    "Subtract from Word Immediate",                                         // SPU_sfi
    "Add Extended",                                                         // SPU_addx
    "Carry Generate",                                                       // SPU_cg
    "Carry Generate Extended",                                              // SPU_cgx
    "Subtract from Extended",                                               // SPU_sfx
    "Borrow Generate",                                                      // SPU_bg
    "Borrow Generate Extended",                                             // SPU_bgx
    "Multiply",                                                             // SPU_mpy
    "Multiply Unsigned",                                                    // SPU_mpyu
    "Multiply Immediate",                                                   // SPU_mpyi
    "Multiply Unsigned Immediate",                                          // SPU_mpyui
    "Multiply High",                                                        // SPU_mpyh
    "Multiply and Shift Right",                                             // SPU_mpys
    "Multiply High High",                                                   // SPU_mpyhh
    "Multiply High High and Add",                                           // SPU_mpyhha
    "Multiply High High Unsigned",                                          // SPU_mpyhhu
    "Multiply High High Unsigned and Add",                                  // SPU_mpyhhau
    "Count Leading Zeros",                                                  // SPU_clz
    "Count Ones in Bytes",                                                  // SPU_cntb
    "Form Select Mask for Bytes",                                           // SPU_fsmb
    "Form Select Mask for Halfwords",                                       // SPU_fsmh
    "Form Select Mask for Words",                                           // SPU_fsm
    "Gather Bits from Bytes",                                               // SPU_gbb
    "Gather Bits from Halfwords",                                           // SPU_gbh
    "Gather Bits from Words",                                               // SPU_gb
    "Average Bytes",                                                        // SPU_avgb
    "Absolute Differences of Bytes",                                        // SPU_absdb
    "Sum Bytes into Halfwords",                                             // SPU_sumb
    "Extend Sign Byte to Halfword",                                         // SPU_xsbh
    "Extend Sign Halfword to Word",                                         // SPU_xshw
    "Extend Sign Word to Doubleword",                                       // SPU_xswd
    "And",                                                                  // SPU_and
    "And with Complement",                                                  // SPU_andc
    "And Byte Immediate",                                                   // SPU_andbi
    "And Halfword Immediate",                                               // SPU_andhi
    "And Word Immediate",                                                   // SPU_andi
    "Or",                                                                   // SPU_or
    "Or with Complement",                                                   // SPU_orc
    "Or Byte Immediate",                                                    // SPU_orbi
    "Or Halfword Immediate",                                                // SPU_orhi
    "Or Word Immediate",                                                    // SPU_ori
    "Or Across",                                                            // SPU_orx
    "Exclusive Or",                                                         // SPU_xor
    "Exclusive Or Byte Immediate",                                          // SPU_xorbi
    "Exclusive Or Halfword Immediate",                                      // SPU_xorhi
    "Exclusive Or Word Immediate",                                          // SPU_xori
    "Nand",                                                                 // SPU_nand
    "Nor",                                                                  // SPU_nor
    "Equivalent",                                                           // SPU_eqv
    "Multiply and Add",                                                     // SPU_mpya
    "Select Bits",                                                          // SPU_selb
    "Shuffle Bytes",                                                        // SPU_shufb

    "Shift Left Halfword",                                                  // SPU_shlh
    "Shift Left Halfword Immediate",                                        // SPU_shlhi
    "Shift Left Word",                                                      // SPU_shl
    "Shift Left Word Immediate",                                            // SPU_shli
    "Shift Left Quadword by Bits",                                          // SPU_shlqbi
    "Shift Left Quadword by Bits Immediate",                                // SPU_shlqbii
    "Shift Left Quadword by Bytes",                                         // SPU_shlqby
    "Shift Left Quadword by Bytes Immediate",                               // SPU_shlqbyi
    "Shift Left Quadword by Bytes from Bit Shift Count",                    // SPU_shlqbybi
    "Rotate Halfword",                                                      // SPU_roth
    "Rotate Halfword Immediate",                                            // SPU_rothi
    "Rotate Word",                                                          // SPU_rot
    "Rotate Word Immediate",                                                // SPU_roti
    "Rotate Quadword by Bytes",                                             // SPU_rotqby
    "Rotate Quadword by Bytes Immediate",                                   // SPU_rotqbyi
    "Rotate Quadword by Bytes from Bit Shift Count",                        // SPU_rotqbybi
    "Rotate Quadword by Bits",                                              // SPU_rotqbi
    "Rotate Quadword by Bits Immediate",                                    // SPU_rotqbii
    "Rotate and Mask Halfword",                                             // SPU_rothm
    "Rotate and Mask Halfword Immediate",                                   // SPU_rothmi
    "Rotate and Mask Word",                                                 // SPU_rotm
    "Rotate and Mask Word Immediate",                                       // SPU_rotmi
    "Rotate and Mask Quadword by Bytes",                                    // SPU_rotqmby
    "Rotate and Mask Quadword by Bytes Immediate",                          // SPU_rotqmbyi
    "Rotate and Mask Quadword Bytes from Bit Shift Count",                  // SPU_rotqmbybi
    "Rotate and Mask Quadword by Bits",                                     // SPU_rotqmbi
    "Rotate and Mask Quadword by Bits Immediate",                           // SPU_rotqmbii
    "Rotate and Mask Algebraic Halfword",                                   // SPU_rotmah
    "Rotate and Mask Algebraic Halfword Immediate",                         // SPU_rotmahi
    "Rotate and Mask Algebraic Word",                                       // SPU_rotma
    "Rotate and Mask Algebraic Word Immediate",                             // SPU_rotmai

    "Halt If Equal",                                                        // SPU_heq
    "Halt If Equal Immediate",                                              // SPU_heqi
    "Halt If Greater Than",                                                 // SPU_hgt
    "Halt If Greater Than Immediate",                                       // SPU_hgti
    "Halt If Logically Greater Than",                                       // SPU_hlgt
    "Halt If Logically Greater Than Immediate",                             // SPU_hlgti
    "Compare Equal Byte",                                                   // SPU_ceqb
    "Compare Equal Byte Immediate",                                         // SPU_ceqbi
    "Compare Equal Halfword",                                               // SPU_ceqh
    "Compare Equal Halfword Immediate",                                     // SPU_ceqhi
    "Compare Equal Word",                                                   // SPU_ceq
    "Compare Equal Word Immediate",                                         // SPU_ceqi
    "Compare Greater Than Byte",                                            // SPU_cgtb
    "Compare Greater Than Byte Immediate",                                  // SPU_cgtbi
    "Compare Greater Than Halfword",                                        // SPU_cgth
    "Compare Greater Than Halfword Immediate",                              // SPU_cgthi
    "Compare Greater Than Word",                                            // SPU_cgt
    "Compare Greater Than Word Immediate",                                  // SPU_cgti
    "Compare Logical Greater Than Byte",                                    // SPU_clgtb
    "Compare Logical Greater Than Byte Immediate",                          // SPU_clgtbi
    "Compare Logical Greater Than Halfword",                                // SPU_clgth
    "Compare Logical Greater Than Halfword Immediate",                      // SPU_clgthi
    "Compare Logical Greater Than Word",                                    // SPU_clgt
    "Compare Logical Greater Than Word Immediate",                          // SPU_clgti
    "Branch Relative",                                                      // SPU_br
    "Branch Absolute",                                                      // SPU_bra
    "Branch Relative and Set Link",                                         // SPU_brsl
    "Branch Absolute and Set Link",                                         // SPU_brasl
    "Branch Indirect",                                                      // SPU_bi
    "Interrupt Return (PC <- SRR0)",                                        // SPU_iret
    "Branch Indirect and Set Link if External Data",                        // SPU_bisled
    "Branch Indirect and Set Link",                                         // SPU_bisl
    "Branch If Not Zero Word",                                              // SPU_brnz
    "Branch If Zero Word",                                                  // SPU_brz
    "Branch If Not Zero Halfword",                                          // SPU_brhnz
    "Branch If Zero Halfword",                                              // SPU_brhz
    "Branch Indirect If Zero",                                              // SPU_biz
    "Branch Indirect If Not Zero",                                          // SPU_binz
    "Branch Indirect If Zero Halfword",                                     // SPU_bihz
    "Branch Indirect If Not Zero Halfword",                                 // SPU_bihnz

    "Hint for Branch (r-form)",                                             // SPU_hbr
    "Hint for Branch (a-form)",                                             // SPU_hbra
    "Hint for Branch Relative",                                             // SPU_hbrr

    "Floating Add",                                                         // SPU_fa
    "Double Floating Add",                                                  // SPU_dfa
    "Floating Subtract",                                                    // SPU_fs
    "Double Floating Subtract",                                             // SPU_dfs
    "Floating Multiply",                                                    // SPU_fm
    "Double Floating Multiply",                                             // SPU_dfm
    "Floating Multiply and Add",                                            // SPU_fma
    "Double Floating Multiply and Add",                                     // SPU_dfma
    "Floating Negative Multiply and Subtract",                              // SPU_fnms
    "Double Floating Negative Multiply and Subtract",                       // SPU_dfnms (fixed!)
    "Floating Multiply and Subtract",                                       // SPU_fms
    "Double Floating Multiply and Subtract",                                // SPU_dfms
    "Double Floating Negative Multiply and Add",                            // SPU_dfnma
    "Floating Reciprocal Estimate",                                         // SPU_frest
    "Floating Reciprocal Absolute Square Root Estimate",                    // SPU_frsqest
    "Floating Interpolate",                                                 // SPU_fi
    "Convert Signed Integer to Floating",                                   // SPU_csflt
    "Convert Floating to Signed Integer",                                   // SPU_cflts
    "Convert Unsigned Integer to Floating",                                 // SPU_cuflt
    "Convert Floating to Unsigned Integer",                                 // SPU_cfltu
    "Floating Round Double to Single",                                      // SPU_frds
    "Floating Extend Single to Double",                                     // SPU_fesd
    "Double Floating Compare Equal",                                        // SPU_dfceq
    "Double Floating Compare Magnitude Equal",                              // SPU_dfcmeq
    "Double Floating Compare Greater Than",                                 // SPU_dfcgt
    "Double Floating Compare Magnitude Greater Than",                       // SPU_dfcmgt
    "Double Floating Test Special Value",                                   // SPU_dftsv
    "Floating Compare Equal",                                               // SPU_fceq
    "Floating Compare Magnitude Equal",                                     // SPU_fcmeq
    "Floating Compare Greater Than",                                        // SPU_fcgt
    "Floating Compare Magnitude Greater Than",                              // SPU_fcmgt
    "Floating-Point Status and Control Register Write",                     // SPU_fscrwr (fixed!)
    "Floating-Point Status and Control Register Read",                      // SPU_fscrrd (fixed!)

    "Stop and Signal",                                                      // SPU_stop
    "Stop and Signal with Dependencies",                                    // SPU_stopd
    "No Operation (Load)",                                                  // SPU_lnop
    "No Operation (Execute)",                                               // SPU_nop
    "Synchronize",                                                          // SPU_sync
    "Synchronize Data",                                                     // SPU_dsync
    "Move from Special-Purpose Register",                                   // SPU_mfspr
    "Move to Special-Purpose Register",                                     // SPU_mtspr

    "Read Channel",                                                         // SPU_rdch
    "Read Channel Count",                                                   // SPU_rchcnt
    "Write Channel",                                                        // SPU_wrch

    "Load Register",                                                        // SPU_lr
};

static_assert(qnumber(kInsnComments) == SPU_last, "kInsnComments must match spu_insn_t enum");

const char *spu_insn_comment(uint16 itype)
{
    if (itype < SPU_last)
        return kInsnComments[itype];
    return nullptr;
}
