#include "debugger.h"
#include "disasm.h"
#include "machine.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        if (cond) {                                                            \
            ++g_pass;                                                          \
        } else {                                                               \
            ++g_fail;                                                          \
            std::fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
        }                                                                      \
    } while (0)

uint32_t EncRRR(uint32_t op4, uint32_t rt, uint32_t ra, uint32_t rb, uint32_t rc) {
    return ((op4 & 0xFu) << 28) | ((rt & 0x7Fu) << 21) | ((rb & 0x7Fu) << 14) |
           ((ra & 0x7Fu) << 7) | (rc & 0x7Fu);
}

uint32_t EncRR(uint32_t op11, uint32_t rt, uint32_t ra, uint32_t rb) {
    return ((op11 & 0x7FFu) << 21) | ((rb & 0x7Fu) << 14) | ((ra & 0x7Fu) << 7) | (rt & 0x7Fu);
}

uint32_t EncRI7(uint32_t op11, uint32_t rt, uint32_t ra, int32_t i7) {
    return ((op11 & 0x7FFu) << 21) | ((static_cast<uint32_t>(i7) & 0x7Fu) << 14) |
           ((ra & 0x7Fu) << 7) | (rt & 0x7Fu);
}

uint32_t EncRI8(uint32_t op10, uint32_t rt, uint32_t ra, uint32_t i8) {
    return ((op10 & 0x3FFu) << 22) | ((i8 & 0xFFu) << 14) | ((ra & 0x7Fu) << 7) | (rt & 0x7Fu);
}

uint32_t EncRI10(uint32_t op8, uint32_t rt, uint32_t ra, int32_t i10) {
    return ((op8 & 0xFFu) << 24) | ((static_cast<uint32_t>(i10) & 0x3FFu) << 14) |
           ((ra & 0x7Fu) << 7) | (rt & 0x7Fu);
}

uint32_t EncRI16(uint32_t op9, uint32_t rt, int32_t i16) {
    return ((op9 & 0x1FFu) << 23) | ((static_cast<uint32_t>(i16) & 0xFFFFu) << 7) | (rt & 0x7Fu);
}

uint32_t EncRI18(uint32_t op7, uint32_t rt, uint32_t i18) {
    return ((op7 & 0x7Fu) << 25) | ((i18 & 0x3FFFFu) << 7) | (rt & 0x7Fu);
}

void WriteProgram(spu::SpuMachine &m, uint32_t base, const std::vector<uint32_t> &insns) {
    for (size_t i = 0; i < insns.size(); ++i) {
        const uint32_t w = insns[i];
        uint8_t b[4] = {
            static_cast<uint8_t>(w >> 24), static_cast<uint8_t>(w >> 16),
            static_cast<uint8_t>(w >> 8), static_cast<uint8_t>(w)
        };
        m.mem.WriteLs(base + static_cast<uint32_t>(i * 4), 4, b);
    }
}

void TestCoreAluAndSimd() {
    spu::SpuMachine m;
    WriteProgram(m, 0x100, {
        EncRI16(0x081, 3, 100),                // il r3, 100
        EncRI16(0x081, 4, 30),                 // il r4, 30
        EncRR(0x0C0, 5, 3, 4),                 // a r5, r3, r4          -> 130
        EncRR(0x040, 6, 4, 3),                 // sf r6, r4, r3         -> r3 - r4 = 70
        EncRI16(0x082, 7, 0x1234),             // ilhu r7, 0x1234
        EncRI16(0x0C1, 7, 0x5678),             // iohl r7, 0x5678       -> 0x12345678
        EncRI7(0x07B, 8, 3, 2),                // shli r8, r3, 2        -> 400
        EncRI7(0x079, 9, 8, -2),               // rotmi r9, r8, -2      -> 100
        EncRI7(0x07F, 10, 3, 1),               // shlhi r10, r3, 1      -> 200
        EncRR(0x3C4, 11, 3, 4),                // mpy r11, r3, r4       -> 3000
        EncRRR(0xC, 12, 3, 4, 5),              // mpya r12, r3, r4, r5  -> 3000 + 130 = 3130
        EncRI10(0x024, 7, 1, 0),               // stqd r7, 0(sp)
        EncRI10(0x034, 13, 1, 0),              // lqd r13, 0(sp)        -> 0x12345678
        EncRR(0x000, 0, 0, 0) | 0x2000u,       // stop 0x2000
    });
    m.Reset(0x100);
    const auto st = m.RunSteps(100);
    CHECK(st.reason == spu::StopReason::StopInsn && st.detail == 0x2000u, "stop 0x2000 triggered");
    CHECK(m.cpu.RegWord(5) == 130u, "a: 100 + 30 == 130");
    CHECK(m.cpu.RegWord(6) == 70u, "sf: 100 - 30 == 70");
    CHECK(m.cpu.RegWord(7) == 0x12345678u, "ilhu+iohl == 0x12345678");
    CHECK(m.cpu.RegWord(8) == 400u, "shli: 100 << 2 == 400");
    CHECK(m.cpu.RegWord(9) == 100u, "rotmi: 400 >> 2 == 100");
    CHECK(m.cpu.RegWord(10) == 200u, "shlhi: 100 << 1 == 200");
    CHECK(m.cpu.RegWord(11) == 3000u, "mpy: 100 * 30 == 3000");
    CHECK(m.cpu.RegWord(12) == 3130u, "mpya: 100 * 30 + 130 == 3130");
    CHECK(m.cpu.RegWord(13) == 0x12345678u, "stqd+lqd roundtrip");
}

void TestShufbSelbAndGenCtrl() {
    spu::SpuMachine m;
    m.Reset(0x200);
    // Insert word 0xDEADBEEF into word slot 2 (offset 8) of r4 using cwd + shufb
    m.cpu.Reg(3) = spu::Quadword::FromWords(0xDEADBEEFu, 0, 0, 0);
    m.cpu.Reg(4) = spu::Quadword::FromWords(0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u);
    m.cpu.Reg(5) = spu::Quadword::FromWords(8u, 0, 0, 0);
    WriteProgram(m, 0x200, {
        EncRI7(0x1F6, 6, 5, 0),                // cwd r6, 0(r5)
        EncRRR(0xB, 7, 3, 4, 6),               // shufb r7, r3, r4, r6
        EncRI16(0x065, 8, 0xF00Fu),            // fsmbi r8, 0xF00F
        EncRRR(0x8, 9, 4, 3, 8),               // selb r9, r4, r3, r8 (w0 from r3, w1..2 from r4, w3 from r3=0)
    });
    m.RunSteps(4);
    CHECK(m.cpu.Reg(7).U32(0) == 0x11111111u && m.cpu.Reg(7).U32(2) == 0xDEADBEEFu &&
          m.cpu.Reg(7).U32(3) == 0x44444444u, "cwd+shufb word insertion");
    CHECK(m.cpu.Reg(9).U32(0) == 0xDEADBEEFu && m.cpu.Reg(9).U32(1) == 0x22222222u &&
          m.cpu.Reg(9).U32(3) == 0x00000000u, "fsmbi+selb select");
}

void TestFloatAndDftsv() {
    spu::SpuMachine m;
    m.Reset(0x300);
    m.cpu.Reg(3) = spu::Quadword::FromWords(10u, 20u, 30u, 40u);
    WriteProgram(m, 0x300, {
        EncRI8(0x1DA, 4, 3, 155),              // csflt r4, r3, 0 -> 10.0, 20.0, 30.0, 40.0
        EncRR(0x2C4, 5, 4, 4),                 // fa r5, r4, r4   -> 20.0, 40.0, 60.0, 80.0
        EncRI8(0x1D8, 6, 5, 173),              // cflts r6, r5, 0 -> 20, 40, 60, 80
        EncRR(0x3B8, 7, 4, 0),                 // fesd r7, r4     -> (10.0, 30.0)
        EncRR(0x2CC, 8, 7, 7),                 // dfa r8, r7, r7  -> (20.0, 60.0)
        EncRI7(0x3BF, 9, 10, 0x60),            // dftsv r9, r10, 0x60 (NaN | +Inf)
    });
    // Put +Inf in double 0 and 1.0 in double 1 of r10
    m.cpu.Reg(10).SetU64(0, 0x7FF0000000000000ULL);
    m.cpu.Reg(10).SetU64(1, 0x3FF0000000000000ULL);
    m.RunSteps(6);
    CHECK(m.cpu.Reg(6).U32(0) == 20u && m.cpu.Reg(6).U32(3) == 80u, "csflt+fa+cflts");
    double d0 = 0.0, d1 = 0.0;
    const uint64_t u0 = m.cpu.Reg(8).U64(0), u1 = m.cpu.Reg(8).U64(1);
    std::memcpy(&d0, &u0, 8);
    std::memcpy(&d1, &u1, 8);
    CHECK(std::fabs(d0 - 20.0) < 1e-9 && std::fabs(d1 - 60.0) < 1e-9, "fesd+dfa");
    CHECK(m.cpu.Reg(9).U64(0) == ~0ULL && m.cpu.Reg(9).U64(1) == 0ULL, "dftsv +Inf detection");
}

void TestInterruptAndHalt() {
    spu::SpuMachine m;
    // Interrupt vector at 0x00000: il r20, 0x77; irete
    WriteProgram(m, 0x000, {
        EncRI16(0x081, 20, 0x77),
        EncRR(0x1AA, 0, 0, 0x10),              // irete (E=1)
    });
    // Main at 0x400: enable interrupts via bie, then nop, then heqi r20, 0x77
    WriteProgram(m, 0x400, {
        EncRI18(0x21, 2, 0x408),               // ila r2, 0x408
        EncRR(0x1A8, 0, 2, 0x10),              // bie r2 (E=1 -> enables IE)
        EncRR(0x201, 0, 0, 0),                 // nop (0x408 - interrupt arrives here!)
        EncRI10(0x07F, 0, 20, 0x77),           // heqi r20, 0x77 -> halts!
    });
    m.Reset(0x400);
    m.channels.Events().SetValue(spu::CH_SPU_WrEventMask, spu::EVT_SPU_DECREMENTER);
    m.channels.Events().RaiseEvent(spu::EVT_SPU_DECREMENTER);

    const auto st = m.RunSteps(10);
    // Acknowledge before irete? Wait: irete re-enabled IE while event was still unacked,
    // so verify r20 == 0x77 and SRR0 == 0x408 after first 4 steps!
    CHECK(m.cpu.RegWord(20) == 0x77u, "Interrupt vector 0x00000 executed and set r20=0x77");
    CHECK(m.channels.Events().Srr0() == 0x408u, "SRR0 captured interrupted PC 0x408");
    (void)st;

    // Now test clean heqi halt directly
    m.channels.Events().ClearEvent(spu::EVT_SPU_DECREMENTER);
    m.cpu.SetPC(0x40C);
    const auto hst = m.Step(true);
    CHECK(hst.reason == spu::StopReason::HaltInsn, "heqi r20, 0x77 halted CPU");
}

void TestMfcDmaAndAtomic() {
    spu::SpuMachine m;
    m.Reset(0x500);
    // Map EA 0x10000000 with test pattern
    const uint8_t src_bytes[16] = {
        0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };
    m.mem.MapMainMemoryData(0x10000000ULL, src_bytes, 16, "host_buf", false);

    // Program: MFC GET 16 bytes from EA 0x10000000 -> LS 0x2000, then PUT LS 0x2000 -> EA 0x20000000
    WriteProgram(m, 0x500, {
        EncRI18(0x21, 3, 0x2000),              // ila r3, 0x2000 (LSA)
        EncRR(0x10D, 3, spu::CH_MFC_LSA, 0),   // wrch MFC_LSA, r3
        EncRI16(0x081, 4, 0),                  // il r4, 0 (EAH)
        EncRR(0x10D, 4, spu::CH_MFC_EAH, 0),   // wrch MFC_EAH, r4
        EncRI16(0x082, 5, 0x1000),             // ilhu r5, 0x1000 (EAL = 0x10000000)
        EncRR(0x10D, 5, spu::CH_MFC_EAL, 0),   // wrch MFC_EAL, r5
        EncRI16(0x081, 6, 16),                 // il r6, 16 (Size)
        EncRR(0x10D, 6, spu::CH_MFC_Size, 0),  // wrch MFC_Size, r6
        EncRI16(0x081, 7, 1),                  // il r7, 1 (TagID)
        EncRR(0x10D, 7, spu::CH_MFC_TagID, 0), // wrch MFC_TagID, r7
        EncRI16(0x081, 8, 0x40),               // il r8, 0x40 (MFC GET)
        EncRR(0x10D, 8, spu::CH_MFC_Cmd, 0),   // wrch MFC_Cmd, r8
        EncRI16(0x081, 9, 2),                  // il r9, (1 << 1) tag mask
        EncRR(0x10D, 9, spu::CH_MFC_WrTagMask, 0),
        EncRI16(0x081, 10, 2),                 // TAG_UPDATE_ALL
        EncRR(0x10D, 10, spu::CH_MFC_WrTagUpdate, 0),
        EncRR(0x00D, 11, spu::CH_MFC_RdTagStat, 0),  // rdch r11, MFC_RdTagStat
        // Now PUT to 0x20000000 (auto-mapped EA)
        EncRI16(0x082, 5, 0x2000),             // ilhu r5, 0x2000
        EncRR(0x10D, 5, spu::CH_MFC_EAL, 0),
        EncRI16(0x081, 8, 0x20),               // il r8, 0x20 (MFC PUT)
        EncRR(0x10D, 8, spu::CH_MFC_Cmd, 0),
        EncRR(0x000, 0, 0, 0) | 1u,            // stop 1
    });
    const auto st = m.RunSteps(50);
    CHECK(st.reason == spu::StopReason::StopInsn, "MFC DMA program stopped cleanly");
    CHECK(m.cpu.RegWord(11) == 2u, "MFC_RdTagStat returned tag mask 0x2");

    uint8_t ls_out[16] = {}, ea_out[16] = {};
    m.mem.ReadLs(0x2000, 16, ls_out);
    m.mem.ReadMainMemory(0x20000000ULL, 16, ea_out);
    CHECK(std::memcmp(ls_out, src_bytes, 16) == 0, "MFC GET copied EA->LS accurately");
    CHECK(std::memcmp(ea_out, src_bytes, 16) == 0, "MFC PUT copied LS->EA accurately");
}

void TestPluggableChannelDevicesAndJson() {
    spu::SpuMachine m;
    const char *cfg = R"JSON({
        "dma_regions": [
            { "name": "keyblob", "ea": "0x30000000", "hex": "0102030405060708" }
        ],
        "devices": [
            {
                "channel": "SPU_RdInMbox",
                "type": "fifo",
                "name": "test_mbox",
                "rx": ["0xCAFE0001", "0xCAFE0002"],
                "on_empty": "break"
            },
            {
                "channel": 64,
                "type": "responder",
                "name": "iso_crypto",
                "rules": [
                    { "when_write": "0x00000010", "reply": ["0xAA11BB22", "0xCC33DD44"], "reply_channel": 65 },
                    { "when_write": "*", "reply": ["0xFFFFFFFF"], "reply_channel": 65 }
                ]
            },
            {
                "channel": "SPU_IsoStat",
                "type": "fifo",
                "name": "iso_stat",
                "on_empty": "break"
            },
            {
                "channel": 70,
                "type": "register",
                "name": "hw_ver",
                "value": "0x00010203",
                "read_only": true
            }
        ]
    })JSON";

    std::string err;
    CHECK(m.channels.LoadConfigJson(cfg, "", &err), "LoadConfigJson succeeded");

    // Verify DMA region loaded from JSON hex
    uint8_t kb[8] = {};
    CHECK(m.mem.ReadMainMemory(0x30000000ULL, 8, kb) && kb[0] == 1 && kb[7] == 8,
          "JSON dma_region hex loaded");

    // Program exercises:
    //  1. rdch r3, SPU_RdInMbox (gets 0xCAFE0001)
    //  2. wrch SPU_IsoCntl(64), 0x10 -> Responder pushes [0xAA11BB22, 0xCC33DD44] into ch65!
    //  3. rchcnt r4, SPU_IsoStat(65) -> 2
    //  4. rdch r5, SPU_IsoStat(65) -> 0xAA11BB22
    //  5. rdch r6, SPU_IsoStat(65) -> 0xCC33DD44
    //  6. rdch r7, ch70 -> 0x00010203 (read-only register)
    //  7. rdch r8, SPU_IsoStat(65) -> empty FIFO triggers ChannelBreak with PC parked on rdch!
    WriteProgram(m, 0x600, {
        EncRR(0x00D, 3, spu::CH_SPU_RdInMbox, 0),
        EncRI16(0x081, 10, 0x10),
        EncRR(0x10D, 10, 64, 0),
        EncRR(0x00F, 4, 65, 0),
        EncRR(0x00D, 5, 65, 0),
        EncRR(0x00D, 6, 65, 0),
        EncRR(0x00D, 7, 70, 0),
        EncRR(0x00D, 8, 65, 0),  // 0x61C: empty -> ChannelBreak!
    });
    m.cpu.Reset(0x600);
    const auto st = m.RunSteps(20);
    CHECK(m.cpu.RegWord(3) == 0xCAFE0001u, "JSON FIFO rx[0] read");
    CHECK(m.cpu.RegWord(4) == 2u, "Responder pushed 2 words into ch65");
    CHECK(m.cpu.RegWord(5) == 0xAA11BB22u && m.cpu.RegWord(6) == 0xCC33DD44u, "Responder replies read");
    CHECK(m.cpu.RegWord(7) == 0x00010203u, "Register device read");
    CHECK(st.reason == spu::StopReason::ChannelBreak && st.pc == 0x61Cu && st.detail == 65u,
          "Empty FIFO triggered ChannelBreak with PC parked on rdch");

    // Manual CLI injection to unblock stalled rdch!
    std::string out;
    CHECK(m.ExecuteCommand("ch push SPU_IsoStat 0x99887766", out), "CLI ch push succeeded");
    const auto st2 = m.Step(true);
    CHECK(st2.reason == spu::StopReason::None && m.cpu.RegWord(8) == 0x99887766u && m.cpu.GetPC() == 0x620u,
          "Resumed after manual ch push and received 0x99887766");

    // Test CallbackChannelDevice
    uint32_t last_wr = 0;
    m.channels.AttachDevice(75, std::make_shared<spu::CallbackChannelDevice>(
        "py_mock",
        [&last_wr](uint8_t ch, char op, uint32_t in_val, uint32_t *val_out) {
            (void)ch;
            if (op == 'W') { last_wr = in_val; return spu::ChannelStatus::Ok; }
            if (op == 'C') { *val_out = 1; return spu::ChannelStatus::Ok; }
            *val_out = last_wr ^ 0x5A5A5A5Au;
            return spu::ChannelStatus::Ok;
        }));
    WriteProgram(m, 0x640, {
        EncRI16(0x081, 12, 0x1234),
        EncRR(0x10D, 12, 75, 0),               // wrch ch75, r12
        EncRR(0x00D, 13, 75, 0),               // rdch r13, ch75 -> 0x1234 ^ 0x5A5A5A5A
    });
    m.cpu.SetPC(0x640);
    m.RunSteps(3);
    CHECK(m.cpu.RegWord(13) == (0x1234u ^ 0x5A5A5A5Au), "CallbackChannelDevice write+read worked");

    // Test JSON export roundtrip
    const std::string exported = m.channels.ExportConfigJson();
    CHECK(exported.find("iso_crypto") != std::string::npos && exported.find("hw_ver") != std::string::npos,
          "ExportConfigJson contains attached devices");
}

void TestGdbAndDisasm() {
    spu::SpuMachine m;
    WriteProgram(m, 0x0, { EncRI16(0x081, 3, 42) });  // il r3, 42
    m.Reset(0);
    CHECK(spu::DisassembleSpu(0, m.mem.FetchInsn(0)) == "il r3, 0x2A", "Standalone disassembler matches");

    spu::GdbServer gdb(&m, 0);
    CHECK(gdb.ProcessPacket("?") == "S05", "GDB ? returns S05");
    CHECK(gdb.ProcessPacket("s") == "S05", "GDB step executes il r3, 42");
    CHECK(m.cpu.RegWord(3) == 42u, "GDB step updated r3 == 42");
    const std::string pc_hex = gdb.ProcessPacket("p81");  // reg 129 = 0x81 = PC
    CHECK(pc_hex == "00000004", "GDB p81 returns big-endian PC 00000004");
}

}  // namespace

int main() {
    TestCoreAluAndSimd();
    TestShufbSelbAndGenCtrl();
    TestFloatAndDftsv();
    TestInterruptAndHalt();
    TestMfcDmaAndAtomic();
    TestPluggableChannelDevicesAndJson();
    TestGdbAndDisasm();

    std::printf("spuemu_tests: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
