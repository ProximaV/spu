#include "cpu.h"

#include "log.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>

namespace spu {

namespace {

inline uint32_t Bits(uint32_t w, int lo, int hi) {
    return (w >> (31 - hi)) & ((1u << (hi - lo + 1)) - 1u);
}

inline int32_t Sext(uint32_t v, int bits) {
    const uint32_t sign = 1u << (bits - 1);
    return static_cast<int32_t>((v ^ sign) - sign);
}

inline uint32_t RotL32(uint32_t v, uint32_t s) {
    s &= 31u;
    return s == 0 ? v : ((v << s) | (v >> (32u - s)));
}

inline uint16_t RotL16(uint16_t v, uint32_t s) {
    s &= 15u;
    return s == 0 ? v : static_cast<uint16_t>((v << s) | (v >> (16u - s)));
}

inline uint8_t PopCount8(uint8_t b) {
    uint8_t c = 0;
    while (b) { c += (b & 1u); b >>= 1; }
    return c;
}

inline uint32_t Clz32(uint32_t v) {
    if (v == 0) return 32u;
    uint32_t n = 0;
    while ((v & 0x80000000u) == 0) { ++n; v <<= 1; }
    return n;
}

Quadword RotQBy(const Quadword &a, uint32_t s) {
    s &= 15u;
    Quadword r;
    for (size_t i = 0; i < 16; ++i) r.b[i] = a.b[(i + s) & 15u];
    return r;
}

Quadword ShlQBy(const Quadword &a, uint32_t s) {
    s &= 31u;
    Quadword r;
    for (size_t i = 0; i < 16; ++i) {
        r.b[i] = (i + s < 16u) ? a.b[i + s] : 0u;
    }
    return r;
}

Quadword RotQmBy(const Quadword &a, uint32_t count) {
    const uint32_t s = (0u - count) & 31u;
    Quadword r;
    for (size_t i = 0; i < 16; ++i) {
        r.b[i] = (i >= s) ? a.b[i - s] : 0u;
    }
    return r;
}

Quadword RotQBi(const Quadword &a, uint32_t s) {
    s &= 7u;
    if (s == 0) return a;
    Quadword r;
    for (size_t i = 0; i < 16; ++i) {
        const uint8_t hi = a.b[i];
        const uint8_t lo = a.b[(i + 1u) & 15u];
        r.b[i] = static_cast<uint8_t>((hi << s) | (lo >> (8u - s)));
    }
    return r;
}

Quadword ShlQBi(const Quadword &a, uint32_t s) {
    s &= 7u;
    if (s == 0) return a;
    Quadword r;
    for (size_t i = 0; i < 16; ++i) {
        const uint8_t hi = a.b[i];
        const uint8_t lo = (i + 1u < 16u) ? a.b[i + 1u] : 0u;
        r.b[i] = static_cast<uint8_t>((hi << s) | (lo >> (8u - s)));
    }
    return r;
}

Quadword RotQmBi(const Quadword &a, uint32_t count) {
    const uint32_t s = (0u - count) & 7u;
    if (s == 0) return a;
    Quadword r;
    for (size_t i = 0; i < 16; ++i) {
        const uint8_t hi = (i > 0) ? a.b[i - 1u] : 0u;
        const uint8_t lo = a.b[i];
        r.b[i] = static_cast<uint8_t>((hi << (8u - s)) | (lo >> s));
    }
    return r;
}

Quadword GenCtrl(uint32_t addr, uint32_t width) {
    Quadword q;
    for (uint8_t i = 0; i < 16; ++i) q.b[i] = static_cast<uint8_t>(0x10u + i);
    const uint32_t mask = ~(width - 1u);
    const uint32_t t = (addr & 15u) & mask;
    const uint8_t base = (width == 1) ? 0x03u : (width == 2) ? 0x02u : 0x00u;
    for (uint32_t k = 0; k < width; ++k) {
        q.b[(t + k) & 15u] = static_cast<uint8_t>(base + k);
    }
    return q;
}

Quadword FsmBytes(uint16_t mask16) {
    Quadword q;
    for (size_t i = 0; i < 16; ++i) {
        q.b[i] = (mask16 & (0x8000u >> i)) ? 0xFFu : 0x00u;
    }
    return q;
}

}  // namespace

SpuCpu::SpuCpu(SpuMemory *mem, ChannelRouter *channels)
    : mem_(mem), channels_(channels) {
    Reset(0);
}

void SpuCpu::Reset(uint32_t entry_pc) {
    for (auto &r : gpr_) r.Clear();
    for (auto &s : spr_) s.Clear();
    fpscr_.Clear();
    // Initialize SP (r1) to top of 256 KB Local Store minus 0x10 (standard SPU ABI stack)
    gpr_[1].SetPrefU32((mem_->Lslr() + 1u) - 0x10u);
    pc_ = (entry_pc & mem_->Lslr()) & ~3u;
    run_state_ = RunState::Running;
    ext_data_pending_ = false;
    total_cycles_ = 0;
    insn_count_ = 0;
}

float SpuCpu::BitsToF32(uint32_t u) {
    float f = 0.0f;
    std::memcpy(&f, &u, sizeof(f));
    return f;
}

uint32_t SpuCpu::F32ToBits(float f) {
    uint32_t u = 0;
    std::memcpy(&u, &f, sizeof(u));
    return u;
}

double SpuCpu::BitsToF64(uint64_t u) {
    double d = 0.0;
    std::memcpy(&d, &u, sizeof(d));
    return d;
}

uint64_t SpuCpu::F64ToBits(double d) {
    uint64_t u = 0;
    std::memcpy(&u, &d, sizeof(u));
    return u;
}

float SpuCpu::FlushDenormF32(uint32_t bits) {
    // SPU single-precision treats exponent 0 as +0.0 (denorms flushed to zero)
    if ((bits & 0x7F800000u) == 0) return 0.0f;
    return BitsToF32(bits);
}

uint32_t SpuCpu::PackSpuF32(float v) {
    const uint32_t b = F32ToBits(v);
    if ((b & 0x7F800000u) == 0) return 0u;  // SPU SP underflow/zero is +0.0
    if (std::isnan(v) || std::isinf(v)) {
        // SPU extended-range SP saturates to max magnitude (0x7FFFFFFF / 0xFFFFFFFF)
        return (b & 0x80000000u) | 0x7FFFFFFFu;
    }
    return b;
}

void SpuCpu::ApplyBranchDE(uint32_t word) {
    const uint32_t rb = (word >> 14) & 0x7Fu;
    if (rb & 0x20u) channels_->Events().SetInterruptEnable(false);
    if (rb & 0x10u) channels_->Events().SetInterruptEnable(true);
}

void SpuCpu::DeliverPendingInterrupt() {
    if (channels_->Events().InterruptEnabled() &&
        channels_->Events().HasMaskedPendingEvent()) {
        channels_->Events().SetSrr0(pc_);
        channels_->Events().SetInterruptEnable(false);
        pc_ = 0u;  // SPU Interrupt Vector = 0x00000
        run_state_ = RunState::Running;
    }
}

StopInfo SpuCpu::Step(bool ignore_bpt) {
    // Check pending interrupt delivery before instruction fetch
    DeliverPendingInterrupt();

    if (!ignore_bpt && HasBreakpoint(pc_)) {
        return StopInfo{StopReason::Breakpoint, pc_, pc_, false, "Breakpoint hit"};
    }

    const uint32_t insn_pc = pc_;
    const uint32_t word = mem_->FetchInsn(insn_pc);
    const StopInfo stop = ExecuteInstruction(insn_pc, word);

    if (stop.reason != StopReason::ChannelStall && stop.reason != StopReason::ChannelBreak) {
        ++insn_count_;
        ++total_cycles_;
        channels_->Tick(1);
    }

    const WatchHit wh = mem_->ConsumeWatchHit();
    if (wh.hit && stop.reason == StopReason::None) {
        return StopInfo{StopReason::Watchpoint, pc_, wh.addr, wh.is_write,
                        wh.is_write ? "LS write watchpoint" : "LS read watchpoint"};
    }
    return stop;
}

StopInfo SpuCpu::ExecuteInstruction(uint32_t insn_pc, uint32_t w) {
    const uint32_t lslr = mem_->Lslr();
    const uint32_t next_pc = (insn_pc + 4u) & lslr;
    pc_ = next_pc;

    const uint32_t rt_idx = w & 0x7Fu;
    const uint32_t ra_idx = (w >> 7) & 0x7Fu;
    const uint32_t rb_idx = (w >> 14) & 0x7Fu;

    // -----------------------------------------------------------------------
    // 1. 4-bit opcodes (RRR: OP4[0:3] RT[4:10] RB[11:17] RA[18:24] RC[25:31])
    // -----------------------------------------------------------------------
    const uint32_t op4 = w >> 28;
    if (op4 == 0x8 || (op4 >= 0xB && op4 <= 0xF)) {
        const uint32_t rrr_rt = (w >> 21) & 0x7Fu;
        const uint32_t rrr_rb = (w >> 14) & 0x7Fu;
        const uint32_t rrr_ra = (w >> 7) & 0x7Fu;
        const uint32_t rrr_rc = w & 0x7Fu;
        const Quadword &A = gpr_[rrr_ra];
        const Quadword &B = gpr_[rrr_rb];
        const Quadword &C = gpr_[rrr_rc];
        Quadword R;

        switch (op4) {
        case 0x8:  // selb
            for (size_t i = 0; i < 16; ++i) {
                R.b[i] = static_cast<uint8_t>((B.b[i] & C.b[i]) | (A.b[i] & ~C.b[i]));
            }
            break;
        case 0xB:  // shufb
            for (size_t i = 0; i < 16; ++i) {
                const uint8_t c = C.b[i];
                if ((c & 0xC0u) == 0x80u) R.b[i] = 0x00u;
                else if ((c & 0xE0u) == 0xC0u) R.b[i] = 0xFFu;
                else if ((c & 0xE0u) == 0xE0u) R.b[i] = 0x80u;
                else {
                    const uint8_t idx = c & 0x1Fu;
                    R.b[i] = (idx < 16u) ? A.b[idx] : B.b[idx - 16u];
                }
            }
            break;
        case 0xC:  // mpya
            for (size_t i = 0; i < 4; ++i) {
                const int32_t a = static_cast<int16_t>(A.U32(i) & 0xFFFFu);
                const int32_t b = static_cast<int16_t>(B.U32(i) & 0xFFFFu);
                R.SetU32(i, static_cast<uint32_t>(a * b + C.S32(i)));
            }
            break;
        case 0xD:  // fnms: -(A * B - C) = C - A * B
            for (size_t i = 0; i < 4; ++i) {
                const float fa = FlushDenormF32(A.U32(i));
                const float fb = FlushDenormF32(B.U32(i));
                const float fc = FlushDenormF32(C.U32(i));
                R.SetU32(i, PackSpuF32(fc - fa * fb));
            }
            break;
        case 0xE:  // fma: A * B + C
            for (size_t i = 0; i < 4; ++i) {
                const float fa = FlushDenormF32(A.U32(i));
                const float fb = FlushDenormF32(B.U32(i));
                const float fc = FlushDenormF32(C.U32(i));
                R.SetU32(i, PackSpuF32(fa * fb + fc));
            }
            break;
        case 0xF:  // fms: A * B - C
            for (size_t i = 0; i < 4; ++i) {
                const float fa = FlushDenormF32(A.U32(i));
                const float fb = FlushDenormF32(B.U32(i));
                const float fc = FlushDenormF32(C.U32(i));
                R.SetU32(i, PackSpuF32(fa * fb - fc));
            }
            break;
        }
        gpr_[rrr_rt] = R;
        return {};
    }

    // -----------------------------------------------------------------------
    // 2. 7-bit opcodes (RI18 / HBRA / HBRR)
    // -----------------------------------------------------------------------
    const uint32_t op7 = w >> 25;
    if (op7 == 0x21) {  // ila
        const uint32_t i18 = Bits(w, 7, 24);
        gpr_[rt_idx] = Quadword::SplatU32(i18);
        return {};
    }
    if (op7 == 0x08 || op7 == 0x09) {  // hbra / hbrr (architectural hint no-op)
        return {};
    }

    // -----------------------------------------------------------------------
    // 3. 8-bit opcodes (RI10)
    // -----------------------------------------------------------------------
    const uint32_t op8 = w >> 24;
    const uint32_t i10raw = Bits(w, 8, 17);
    const int32_t i10s = Sext(i10raw, 10);
    const uint8_t i10b8 = static_cast<uint8_t>(i10raw & 0xFFu);
    const int8_t i10b8s = static_cast<int8_t>(i10b8);
    const Quadword &RA = gpr_[ra_idx];

    switch (op8) {
    case 0x04: {  // ori
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) | static_cast<uint32_t>(i10s));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x05: {  // orhi
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RA.U16(i) | imm);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x06: {  // orbi
        Quadword R;
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(RA.b[i] | i10b8);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x0C: {  // sfi: imm - RA
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, static_cast<uint32_t>(i10s) - RA.U32(i));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x0D: {  // sfhi: imm - RA
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, static_cast<uint16_t>(imm - RA.U16(i)));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x14: {  // andi
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) & static_cast<uint32_t>(i10s));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x15: {  // andhi
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RA.U16(i) & imm);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x16: {  // andbi
        Quadword R;
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(RA.b[i] & i10b8);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x1C: {  // ai
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) + static_cast<uint32_t>(i10s));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x1D: {  // ahi
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, static_cast<uint16_t>(RA.U16(i) + imm));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x24: {  // stqd
        const uint32_t addr = RA.PrefU32() + static_cast<uint32_t>(i10s << 4);
        mem_->StoreQuadword(addr, gpr_[rt_idx]);
        return {};
    }
    case 0x34: {  // lqd
        const uint32_t addr = RA.PrefU32() + static_cast<uint32_t>(i10s << 4);
        gpr_[rt_idx] = mem_->LoadQuadword(addr);
        return {};
    }
    case 0x44: {  // xori
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) ^ static_cast<uint32_t>(i10s));
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x45: {  // xorhi
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RA.U16(i) ^ imm);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x46: {  // xorbi
        Quadword R;
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(RA.b[i] ^ i10b8);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x4C: {  // cgti
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, (RA.S32(i) > i10s) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x4D: {  // cgthi
        const int16_t imm = static_cast<int16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, (RA.S16(i) > imm) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x4E: {  // cgtbi
        Quadword R;
        for (size_t i = 0; i < 16; ++i) R.b[i] = (RA.S8(i) > i10b8s) ? 0xFFu : 0u;
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x4F: {  // hgti
        if (RA.PrefS32() > i10s) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::HaltInsn, insn_pc, static_cast<uint32_t>(i10s), false, "hgti triggered"};
        }
        return {};
    }
    case 0x5C: {  // clgti
        const uint32_t imm = static_cast<uint32_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, (RA.U32(i) > imm) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x5D: {  // clgthi
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, (RA.U16(i) > imm) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x5E: {  // clgtbi
        Quadword R;
        for (size_t i = 0; i < 16; ++i) R.b[i] = (RA.b[i] > i10b8) ? 0xFFu : 0u;
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x5F: {  // hlgti
        if (RA.PrefU32() > static_cast<uint32_t>(i10s)) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::HaltInsn, insn_pc, static_cast<uint32_t>(i10s), false, "hlgti triggered"};
        }
        return {};
    }
    case 0x74: {  // mpyi
        Quadword R;
        for (size_t i = 0; i < 4; ++i) {
            const int32_t a = static_cast<int16_t>(RA.U32(i) & 0xFFFFu);
            R.SetU32(i, static_cast<uint32_t>(a * i10s));
        }
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x75: {  // mpyui
        const uint32_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t a = RA.U32(i) & 0xFFFFu;
            R.SetU32(i, a * imm);
        }
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x7C: {  // ceqi
        const uint32_t imm = static_cast<uint32_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, (RA.U32(i) == imm) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x7D: {  // ceqhi
        const uint16_t imm = static_cast<uint16_t>(i10s);
        Quadword R;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, (RA.U16(i) == imm) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x7E: {  // ceqbi
        Quadword R;
        for (size_t i = 0; i < 16; ++i) R.b[i] = (RA.b[i] == i10b8) ? 0xFFu : 0u;
        gpr_[rt_idx] = R;
        return {};
    }
    case 0x7F: {  // heqi
        if (RA.PrefU32() == static_cast<uint32_t>(i10s)) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::HaltInsn, insn_pc, static_cast<uint32_t>(i10s), false, "heqi triggered"};
        }
        return {};
    }
    default:
        break;
    }

    // -----------------------------------------------------------------------
    // 4. 9-bit opcodes (RI16)
    // -----------------------------------------------------------------------
    const uint32_t op9 = w >> 23;
    const uint32_t i16u = Bits(w, 9, 24);
    const int32_t i16s = Sext(i16u, 16);
    const uint32_t abs_a = static_cast<uint32_t>(i16s << 2) & lslr;
    const uint32_t rel_a = (insn_pc + static_cast<uint32_t>(i16s << 2)) & lslr;

    switch (op9) {
    case 0x040:  // brz
        if (gpr_[rt_idx].PrefU32() == 0) pc_ = rel_a;
        return {};
    case 0x041:  // stqa
        mem_->StoreQuadword(abs_a, gpr_[rt_idx]);
        return {};
    case 0x042:  // brnz
        if (gpr_[rt_idx].PrefU32() != 0) pc_ = rel_a;
        return {};
    case 0x044:  // brhz
        if (gpr_[rt_idx].U16(1) == 0) pc_ = rel_a;  // preferred halfword slot = bytes 2:3
        return {};
    case 0x046:  // brhnz
        if (gpr_[rt_idx].U16(1) != 0) pc_ = rel_a;
        return {};
    case 0x047:  // stqr
        mem_->StoreQuadword(rel_a, gpr_[rt_idx]);
        return {};
    case 0x060:  // bra
        pc_ = abs_a;
        return {};
    case 0x061:  // lqa
        gpr_[rt_idx] = mem_->LoadQuadword(abs_a);
        return {};
    case 0x062:  // brasl
        gpr_[rt_idx] = Quadword::FromWords(next_pc, 0, 0, 0);
        pc_ = abs_a;
        return {};
    case 0x064:  // br
        pc_ = rel_a;
        return {};
    case 0x065:  // fsmbi
        gpr_[rt_idx] = FsmBytes(static_cast<uint16_t>(i16u));
        return {};
    case 0x066:  // brsl
        gpr_[rt_idx] = Quadword::FromWords(next_pc, 0, 0, 0);
        pc_ = rel_a;
        return {};
    case 0x067:  // lqr
        gpr_[rt_idx] = mem_->LoadQuadword(rel_a);
        return {};
    case 0x081:  // il
        gpr_[rt_idx] = Quadword::SplatU32(static_cast<uint32_t>(i16s));
        return {};
    case 0x082:  // ilhu
        gpr_[rt_idx] = Quadword::SplatU32(i16u << 16);
        return {};
    case 0x083:  // ilh
        gpr_[rt_idx] = Quadword::SplatU16(static_cast<uint16_t>(i16u));
        return {};
    case 0x0C1: {  // iohl
        for (size_t i = 0; i < 4; ++i) gpr_[rt_idx].SetU32(i, gpr_[rt_idx].U32(i) | i16u);
        return {};
    }
    default:
        break;
    }

    // -----------------------------------------------------------------------
    // 5. 10-bit opcodes (RI8 float conversions)
    // -----------------------------------------------------------------------
    const uint32_t op10 = w >> 22;
    if (op10 >= 0x1D8 && op10 <= 0x1DB) {
        const int i8 = static_cast<int>(Bits(w, 10, 17));
        const int bias = (op10 <= 0x1D9) ? 173 : 155;
        const int scale = bias - i8;
        if (scale < 0 || scale > 127) {
            return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "Invalid float scale"};
        }
        Quadword R;
        const double factor = std::ldexp(1.0, (op10 <= 0x1D9) ? scale : -scale);
        for (size_t i = 0; i < 4; ++i) {
            if (op10 == 0x1D8) {  // cflts
                const double v = static_cast<double>(FlushDenormF32(RA.U32(i))) * factor;
                if (v >= 2147483647.0) R.SetU32(i, 0x7FFFFFFFu);
                else if (v <= -2147483648.0) R.SetU32(i, 0x80000000u);
                else R.SetU32(i, static_cast<uint32_t>(static_cast<int32_t>(v)));
            } else if (op10 == 0x1D9) {  // cfltu
                const double v = static_cast<double>(FlushDenormF32(RA.U32(i))) * factor;
                if (v >= 4294967295.0) R.SetU32(i, 0xFFFFFFFFu);
                else if (v <= 0.0) R.SetU32(i, 0u);
                else R.SetU32(i, static_cast<uint32_t>(v));
            } else if (op10 == 0x1DA) {  // csflt
                const float f = static_cast<float>(static_cast<double>(RA.S32(i)) * factor);
                R.SetU32(i, PackSpuF32(f));
            } else {  // cuflt
                const float f = static_cast<float>(static_cast<double>(RA.U32(i)) * factor);
                R.SetU32(i, PackSpuF32(f));
            }
        }
        gpr_[rt_idx] = R;
        return {};
    }

    // -----------------------------------------------------------------------
    // 6. 11-bit opcodes (RR, RI7, Control, Channel, Branches, Float)
    // -----------------------------------------------------------------------
    const uint32_t op11 = w >> 21;
    const Quadword &RB = gpr_[rb_idx];
    const Quadword &RT = gpr_[rt_idx];
    const int32_t i7s = Sext(rb_idx, 7);
    Quadword R;

    switch (op11) {
    case 0x000: {  // stop
        if ((w & 0x001FC000u) != 0) {
            return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "stop reserved bits non-zero"};
        }
        const uint32_t sig = w & 0x3FFFu;
        run_state_ = RunState::Stopped;
        char msgbuf[64];
        std::snprintf(msgbuf, sizeof(msgbuf), "stop 0x%X", sig);
        return StopInfo{StopReason::StopInsn, insn_pc, sig, false, msgbuf};
    }
    case 0x001:  // lnop
    case 0x002:  // sync / syncc
    case 0x003:  // dsync
    case 0x1AC:  // hbr / hbrp
    case 0x201:  // nop
        return {};

    case 0x00C:  // mfspr
        gpr_[rt_idx] = spr_[ra_idx];
        return {};
    case 0x10C:  // mtspr
        spr_[ra_idx] = gpr_[rt_idx];
        return {};

    case 0x00D: {  // rdch
        const ChannelReadResult res = channels_->ReadChannel(static_cast<uint8_t>(ra_idx), insn_pc, total_cycles_);
        if (res.status == ChannelStatus::Stalled) {
            pc_ = insn_pc;
            run_state_ = RunState::ChannelStalled;
            return StopInfo{StopReason::ChannelStall, insn_pc, ra_idx, false, res.reason};
        }
        if (res.status == ChannelStatus::Break) {
            pc_ = insn_pc;  // Keep PC on rdch so user can push data and resume!
            run_state_ = RunState::ChannelStalled;
            return StopInfo{StopReason::ChannelBreak, insn_pc, ra_idx, false, res.reason};
        }
        gpr_[rt_idx] = Quadword::FromWords(res.value, 0, 0, 0);
        run_state_ = RunState::Running;
        return {};
    }
    case 0x00F: {  // rchcnt
        const uint32_t cnt = channels_->ReadChannelCount(static_cast<uint8_t>(ra_idx), insn_pc, total_cycles_);
        gpr_[rt_idx] = Quadword::FromWords(cnt, 0, 0, 0);
        return {};
    }
    case 0x10D: {  // wrch
        const uint32_t val = gpr_[rt_idx].PrefU32();
        const ChannelWriteResult res = channels_->WriteChannel(static_cast<uint8_t>(ra_idx), val, insn_pc, total_cycles_);
        if (res.status == ChannelStatus::Stalled) {
            pc_ = insn_pc;
            run_state_ = RunState::ChannelStalled;
            return StopInfo{StopReason::ChannelStall, insn_pc, ra_idx, true, res.reason};
        }
        if (res.status == ChannelStatus::Break) {
            return StopInfo{StopReason::ChannelBreak, insn_pc, ra_idx, true, res.reason};
        }
        return {};
    }

    // --- Integer Arithmetic ---
    case 0x0C0:  // a
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) + RB.U32(i));
        gpr_[rt_idx] = R; return {};
    case 0x0C8:  // ah
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, static_cast<uint16_t>(RA.U16(i) + RB.U16(i)));
        gpr_[rt_idx] = R; return {};
    case 0x040:  // sf (RB - RA)
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RB.U32(i) - RA.U32(i));
        gpr_[rt_idx] = R; return {};
    case 0x048:  // sfh (RB - RA)
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, static_cast<uint16_t>(RB.U16(i) - RA.U16(i)));
        gpr_[rt_idx] = R; return {};
    case 0x0C2:  // cg
        for (size_t i = 0; i < 4; ++i) {
            const uint64_t sum = static_cast<uint64_t>(RA.U32(i)) + RB.U32(i);
            R.SetU32(i, static_cast<uint32_t>(sum >> 32));
        }
        gpr_[rt_idx] = R; return {};
    case 0x042:  // bg (1 if RB >= RA else 0)
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, (RB.U32(i) >= RA.U32(i)) ? 1u : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x340:  // addx
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) + RB.U32(i) + (RT.U32(i) & 1u));
        gpr_[rt_idx] = R; return {};
    case 0x341:  // sfx (RB + ~RA + (RT & 1))
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RB.U32(i) + ~RA.U32(i) + (RT.U32(i) & 1u));
        gpr_[rt_idx] = R; return {};
    case 0x342:  // cgx
        for (size_t i = 0; i < 4; ++i) {
            const uint64_t sum = static_cast<uint64_t>(RA.U32(i)) + RB.U32(i) + (RT.U32(i) & 1u);
            R.SetU32(i, static_cast<uint32_t>(sum >> 32));
        }
        gpr_[rt_idx] = R; return {};
    case 0x343:  // bgx
        for (size_t i = 0; i < 4; ++i) {
            const uint64_t sum = static_cast<uint64_t>(RB.U32(i)) + static_cast<uint32_t>(~RA.U32(i)) + (RT.U32(i) & 1u);
            R.SetU32(i, static_cast<uint32_t>(sum >> 32));
        }
        gpr_[rt_idx] = R; return {};

    // --- Logical ---
    case 0x0C1:  // and
        for (size_t i = 0; i < 16; ++i) R.b[i] = RA.b[i] & RB.b[i];
        gpr_[rt_idx] = R; return {};
    case 0x2C1:  // andc
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(RA.b[i] & ~RB.b[i]);
        gpr_[rt_idx] = R; return {};
    case 0x041:  // or
        for (size_t i = 0; i < 16; ++i) R.b[i] = RA.b[i] | RB.b[i];
        gpr_[rt_idx] = R; return {};
    case 0x2C9:  // orc
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(RA.b[i] | ~RB.b[i]);
        gpr_[rt_idx] = R; return {};
    case 0x241:  // xor
        for (size_t i = 0; i < 16; ++i) R.b[i] = RA.b[i] ^ RB.b[i];
        gpr_[rt_idx] = R; return {};
    case 0x0C9:  // nand
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(~(RA.b[i] & RB.b[i]));
        gpr_[rt_idx] = R; return {};
    case 0x049:  // nor
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(~(RA.b[i] | RB.b[i]));
        gpr_[rt_idx] = R; return {};
    case 0x249:  // eqv
        for (size_t i = 0; i < 16; ++i) R.b[i] = static_cast<uint8_t>(~(RA.b[i] ^ RB.b[i]));
        gpr_[rt_idx] = R; return {};
    case 0x1F0:  // orx
        gpr_[rt_idx] = Quadword::FromWords(RA.U32(0) | RA.U32(1) | RA.U32(2) | RA.U32(3), 0, 0, 0);
        return {};

    // --- Byte / Bit / Sign-Extend Utilities ---
    case 0x053:  // absdb
        for (size_t i = 0; i < 16; ++i) {
            const int d = static_cast<int>(RB.b[i]) - static_cast<int>(RA.b[i]);
            R.b[i] = static_cast<uint8_t>(d < 0 ? -d : d);
        }
        gpr_[rt_idx] = R; return {};
    case 0x0D3:  // avgb
        for (size_t i = 0; i < 16; ++i) {
            R.b[i] = static_cast<uint8_t>((static_cast<uint32_t>(RA.b[i]) + RB.b[i] + 1u) >> 1);
        }
        gpr_[rt_idx] = R; return {};
    case 0x253:  // sumb
        for (size_t w_i = 0; w_i < 4; ++w_i) {
            const size_t bo = w_i * 4;
            const uint16_t sb = static_cast<uint16_t>(RB.b[bo] + RB.b[bo + 1] + RB.b[bo + 2] + RB.b[bo + 3]);
            const uint16_t sa = static_cast<uint16_t>(RA.b[bo] + RA.b[bo + 1] + RA.b[bo + 2] + RA.b[bo + 3]);
            R.SetU16(w_i * 2, sb);
            R.SetU16(w_i * 2 + 1, sa);
        }
        gpr_[rt_idx] = R; return {};
    case 0x2A5:  // clz
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, Clz32(RA.U32(i)));
        gpr_[rt_idx] = R; return {};
    case 0x2B4:  // cntb
        for (size_t i = 0; i < 16; ++i) R.b[i] = PopCount8(RA.b[i]);
        gpr_[rt_idx] = R; return {};
    case 0x2B6:  // xsbh
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, static_cast<uint16_t>(static_cast<int16_t>(RA.S8(i * 2 + 1))));
        gpr_[rt_idx] = R; return {};
    case 0x2AE:  // xshw
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, static_cast<uint32_t>(static_cast<int32_t>(RA.S16(i * 2 + 1))));
        gpr_[rt_idx] = R; return {};
    case 0x2A6:  // xswd
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, static_cast<uint64_t>(static_cast<int64_t>(RA.S32(i * 2 + 1))));
        gpr_[rt_idx] = R; return {};

    // --- Gather Bits & Form Select Masks ---
    case 0x1B0: {  // gb
        uint32_t m = 0;
        for (size_t i = 0; i < 4; ++i) m = (m << 1) | (RA.U32(i) & 1u);
        gpr_[rt_idx] = Quadword::FromWords(m, 0, 0, 0);
        return {};
    }
    case 0x1B1: {  // gbh
        uint32_t m = 0;
        for (size_t i = 0; i < 8; ++i) m = (m << 1) | (RA.U16(i) & 1u);
        gpr_[rt_idx] = Quadword::FromWords(m, 0, 0, 0);
        return {};
    }
    case 0x1B2: {  // gbb
        uint32_t m = 0;
        for (size_t i = 0; i < 16; ++i) m = (m << 1) | (RA.b[i] & 1u);
        gpr_[rt_idx] = Quadword::FromWords(m, 0, 0, 0);
        return {};
    }
    case 0x1B4: {  // fsm
        const uint32_t m = RA.PrefU32() & 0xFu;
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, (m & (8u >> i)) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    }
    case 0x1B5: {  // fsmh
        const uint32_t m = RA.PrefU32() & 0xFFu;
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, (m & (0x80u >> i)) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    }
    case 0x1B6:  // fsmb
        gpr_[rt_idx] = FsmBytes(static_cast<uint16_t>(RA.PrefU32() & 0xFFFFu));
        return {};

    // --- Multiply ---
    case 0x3C4:  // mpy
        for (size_t i = 0; i < 4; ++i) {
            const int32_t a = static_cast<int16_t>(RA.U32(i) & 0xFFFFu);
            const int32_t b = static_cast<int16_t>(RB.U32(i) & 0xFFFFu);
            R.SetU32(i, static_cast<uint32_t>(a * b));
        }
        gpr_[rt_idx] = R; return {};
    case 0x3CC:  // mpyu
        for (size_t i = 0; i < 4; ++i) {
            R.SetU32(i, (RA.U32(i) & 0xFFFFu) * (RB.U32(i) & 0xFFFFu));
        }
        gpr_[rt_idx] = R; return {};
    case 0x3C5:  // mpyh
        for (size_t i = 0; i < 4; ++i) {
            const int32_t a = static_cast<int16_t>(RA.U32(i) >> 16);
            const int32_t b = static_cast<int16_t>(RB.U32(i) & 0xFFFFu);
            R.SetU32(i, static_cast<uint32_t>(a * b) << 16);
        }
        gpr_[rt_idx] = R; return {};
    case 0x3C7:  // mpys
        for (size_t i = 0; i < 4; ++i) {
            const int32_t a = static_cast<int16_t>(RA.U32(i) & 0xFFFFu);
            const int32_t b = static_cast<int16_t>(RB.U32(i) & 0xFFFFu);
            R.SetU32(i, static_cast<uint32_t>((a * b) >> 16));
        }
        gpr_[rt_idx] = R; return {};
    case 0x3C6:  // mpyhh
        for (size_t i = 0; i < 4; ++i) {
            const int32_t a = static_cast<int16_t>(RA.U32(i) >> 16);
            const int32_t b = static_cast<int16_t>(RB.U32(i) >> 16);
            R.SetU32(i, static_cast<uint32_t>(a * b));
        }
        gpr_[rt_idx] = R; return {};
    case 0x3CE:  // mpyhhu
        for (size_t i = 0; i < 4; ++i) {
            R.SetU32(i, (RA.U32(i) >> 16) * (RB.U32(i) >> 16));
        }
        gpr_[rt_idx] = R; return {};
    case 0x346:  // mpyhha
        for (size_t i = 0; i < 4; ++i) {
            const int32_t a = static_cast<int16_t>(RA.U32(i) >> 16);
            const int32_t b = static_cast<int16_t>(RB.U32(i) >> 16);
            R.SetU32(i, static_cast<uint32_t>(RT.S32(i) + a * b));
        }
        gpr_[rt_idx] = R; return {};
    case 0x34E:  // mpyhhau
        for (size_t i = 0; i < 4; ++i) {
            R.SetU32(i, RT.U32(i) + (RA.U32(i) >> 16) * (RB.U32(i) >> 16));
        }
        gpr_[rt_idx] = R; return {};

    // --- Shifts & Rotates (Element-wise) ---
    case 0x058:  // rot
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RotL32(RA.U32(i), RB.U32(i)));
        gpr_[rt_idx] = R; return {};
    case 0x078:  // roti
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RotL32(RA.U32(i), static_cast<uint32_t>(i7s)));
        gpr_[rt_idx] = R; return {};
    case 0x059:  // rotm
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t s = (0u - RB.U32(i)) & 0x3Fu;
            R.SetU32(i, s >= 32u ? 0u : (RA.U32(i) >> s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x079:  // rotmi
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t s = (0u - static_cast<uint32_t>(i7s)) & 0x3Fu;
            R.SetU32(i, s >= 32u ? 0u : (RA.U32(i) >> s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x05A:  // rotma
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t s = (0u - RB.U32(i)) & 0x3Fu;
            R.SetU32(i, static_cast<uint32_t>(s >= 32u ? (RA.S32(i) < 0 ? -1 : 0) : (RA.S32(i) >> s)));
        }
        gpr_[rt_idx] = R; return {};
    case 0x07A:  // rotmai
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t s = (0u - static_cast<uint32_t>(i7s)) & 0x3Fu;
            R.SetU32(i, static_cast<uint32_t>(s >= 32u ? (RA.S32(i) < 0 ? -1 : 0) : (RA.S32(i) >> s)));
        }
        gpr_[rt_idx] = R; return {};
    case 0x05B:  // shl
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t s = RB.U32(i) & 0x3Fu;
            R.SetU32(i, s >= 32u ? 0u : (RA.U32(i) << s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x07B:  // shli
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t s = static_cast<uint32_t>(i7s) & 0x3Fu;
            R.SetU32(i, s >= 32u ? 0u : (RA.U32(i) << s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x05C:  // roth
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RotL16(RA.U16(i), RB.U16(i)));
        gpr_[rt_idx] = R; return {};
    case 0x07C:  // rothi
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RotL16(RA.U16(i), static_cast<uint32_t>(i7s)));
        gpr_[rt_idx] = R; return {};
    case 0x05D:  // rothm
        for (size_t i = 0; i < 8; ++i) {
            const uint32_t s = (0u - RB.U16(i)) & 0x1Fu;
            R.SetU16(i, s >= 16u ? 0u : static_cast<uint16_t>(RA.U16(i) >> s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x07D:  // rothmi
        for (size_t i = 0; i < 8; ++i) {
            const uint32_t s = (0u - static_cast<uint32_t>(i7s)) & 0x1Fu;
            R.SetU16(i, s >= 16u ? 0u : static_cast<uint16_t>(RA.U16(i) >> s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x05E:  // rotmah
        for (size_t i = 0; i < 8; ++i) {
            const uint32_t s = (0u - RB.U16(i)) & 0x1Fu;
            R.SetU16(i, static_cast<uint16_t>(s >= 16u ? (RA.S16(i) < 0 ? -1 : 0) : (RA.S16(i) >> s)));
        }
        gpr_[rt_idx] = R; return {};
    case 0x07E:  // rotmahi
        for (size_t i = 0; i < 8; ++i) {
            const uint32_t s = (0u - static_cast<uint32_t>(i7s)) & 0x1Fu;
            R.SetU16(i, static_cast<uint16_t>(s >= 16u ? (RA.S16(i) < 0 ? -1 : 0) : (RA.S16(i) >> s)));
        }
        gpr_[rt_idx] = R; return {};
    case 0x05F:  // shlh
        for (size_t i = 0; i < 8; ++i) {
            const uint32_t s = RB.U16(i) & 0x1Fu;
            R.SetU16(i, s >= 16u ? 0u : static_cast<uint16_t>(RA.U16(i) << s));
        }
        gpr_[rt_idx] = R; return {};
    case 0x07F:  // shlhi (RI7!)
        for (size_t i = 0; i < 8; ++i) {
            const uint32_t s = static_cast<uint32_t>(i7s) & 0x1Fu;
            R.SetU16(i, s >= 16u ? 0u : static_cast<uint16_t>(RA.U16(i) << s));
        }
        gpr_[rt_idx] = R; return {};

    // --- Quadword Shifts & Rotates ---
    case 0x1CC: gpr_[rt_idx] = RotQBy(RA, RB.PrefU32() >> 3); return {};      // rotqbybi
    case 0x1CD: gpr_[rt_idx] = RotQmBy(RA, RB.PrefU32() >> 3); return {};     // rotqmbybi
    case 0x1CF: gpr_[rt_idx] = ShlQBy(RA, RB.PrefU32() >> 3); return {};      // shlqbybi
    case 0x1D8: gpr_[rt_idx] = RotQBi(RA, RB.PrefU32()); return {};           // rotqbi
    case 0x1D9: gpr_[rt_idx] = RotQmBi(RA, RB.PrefU32()); return {};          // rotqmbi
    case 0x1DB: gpr_[rt_idx] = ShlQBi(RA, RB.PrefU32()); return {};           // shlqbi
    case 0x1DC: gpr_[rt_idx] = RotQBy(RA, RB.PrefU32()); return {};           // rotqby
    case 0x1DD: gpr_[rt_idx] = RotQmBy(RA, RB.PrefU32()); return {};          // rotqmby
    case 0x1DF: gpr_[rt_idx] = ShlQBy(RA, RB.PrefU32()); return {};           // shlqby
    case 0x1F8: gpr_[rt_idx] = RotQBi(RA, static_cast<uint32_t>(i7s)); return {};   // rotqbii
    case 0x1F9: gpr_[rt_idx] = RotQmBi(RA, static_cast<uint32_t>(i7s)); return {};  // rotqmbii
    case 0x1FB: gpr_[rt_idx] = ShlQBi(RA, static_cast<uint32_t>(i7s)); return {};   // shlqbii
    case 0x1FC: gpr_[rt_idx] = RotQBy(RA, static_cast<uint32_t>(i7s)); return {};   // rotqbyi
    case 0x1FD: gpr_[rt_idx] = RotQmBy(RA, static_cast<uint32_t>(i7s)); return {};  // rotqmbyi
    case 0x1FF: gpr_[rt_idx] = ShlQBy(RA, static_cast<uint32_t>(i7s)); return {};   // shlqbyi

    // --- Load/Store X-Form & Generate Controls ---
    case 0x144:  // stqx
        mem_->StoreQuadword(RA.PrefU32() + RB.PrefU32(), gpr_[rt_idx]);
        return {};
    case 0x1C4:  // lqx
        gpr_[rt_idx] = mem_->LoadQuadword(RA.PrefU32() + RB.PrefU32());
        return {};
    case 0x1D4: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + RB.PrefU32(), 1); return {};  // cbx
    case 0x1D5: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + RB.PrefU32(), 2); return {};  // chx
    case 0x1D6: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + RB.PrefU32(), 4); return {};  // cwx
    case 0x1D7: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + RB.PrefU32(), 8); return {};  // cdx
    case 0x1F4: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + static_cast<uint32_t>(i7s), 1); return {};  // cbd
    case 0x1F5: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + static_cast<uint32_t>(i7s), 2); return {};  // chd
    case 0x1F6: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + static_cast<uint32_t>(i7s), 4); return {};  // cwd
    case 0x1F7: gpr_[rt_idx] = GenCtrl(RA.PrefU32() + static_cast<uint32_t>(i7s), 8); return {};  // cdd

    // --- Indirect Branches & Stopd ---
    case 0x140:  // stopd
        run_state_ = RunState::Stopped;
        return StopInfo{StopReason::StopdInsn, insn_pc, w, false, "stopd executed"};

    case 0x1A8:  // bi
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "bi D=E=1"};
        pc_ = (RA.PrefU32() & lslr) & ~3u;
        ApplyBranchDE(w);
        return {};
    case 0x1A9: {  // bisl
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "bisl D=E=1"};
        const uint32_t target = (RA.PrefU32() & lslr) & ~3u;
        gpr_[rt_idx] = Quadword::FromWords(next_pc, 0, 0, 0);
        pc_ = target;
        ApplyBranchDE(w);
        return {};
    }
    case 0x1AA:  // iret
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "iret D=E=1"};
        pc_ = (channels_->Events().Srr0() & lslr) & ~3u;
        ApplyBranchDE(w);
        return {};
    case 0x1AB: {  // bisled
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "bisled D=E=1"};
        const uint32_t target = (RA.PrefU32() & lslr) & ~3u;
        gpr_[rt_idx] = Quadword::FromWords(next_pc, 0, 0, 0);
        if (ext_data_pending_) {
            pc_ = target;
            ApplyBranchDE(w);
        }
        return {};
    }
    case 0x128:  // biz
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "biz D=E=1"};
        if (RT.PrefU32() == 0) { pc_ = (RA.PrefU32() & lslr) & ~3u; ApplyBranchDE(w); }
        return {};
    case 0x129:  // binz
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "binz D=E=1"};
        if (RT.PrefU32() != 0) { pc_ = (RA.PrefU32() & lslr) & ~3u; ApplyBranchDE(w); }
        return {};
    case 0x12A:  // bihz
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "bihz D=E=1"};
        if (RT.U16(1) == 0) { pc_ = (RA.PrefU32() & lslr) & ~3u; ApplyBranchDE(w); }
        return {};
    case 0x12B:  // bihnz
        if ((rb_idx & 0x30u) == 0x30u) return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, "bihnz D=E=1"};
        if (RT.U16(1) != 0) { pc_ = (RA.PrefU32() & lslr) & ~3u; ApplyBranchDE(w); }
        return {};

    // --- Integer Compares & Halts ---
    case 0x3C0:  // ceq
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) == RB.U32(i) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x3C8:  // ceqh
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RA.U16(i) == RB.U16(i) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x3D0:  // ceqb
        for (size_t i = 0; i < 16; ++i) R.b[i] = RA.b[i] == RB.b[i] ? 0xFFu : 0u;
        gpr_[rt_idx] = R; return {};
    case 0x240:  // cgt
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.S32(i) > RB.S32(i) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x248:  // cgth
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RA.S16(i) > RB.S16(i) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x250:  // cgtb
        for (size_t i = 0; i < 16; ++i) R.b[i] = RA.S8(i) > RB.S8(i) ? 0xFFu : 0u;
        gpr_[rt_idx] = R; return {};
    case 0x2C0:  // clgt
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, RA.U32(i) > RB.U32(i) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x2C8:  // clgth
        for (size_t i = 0; i < 8; ++i) R.SetU16(i, RA.U16(i) > RB.U16(i) ? 0xFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x2D0:  // clgtb
        for (size_t i = 0; i < 16; ++i) R.b[i] = RA.b[i] > RB.b[i] ? 0xFFu : 0u;
        gpr_[rt_idx] = R; return {};
    case 0x3D8:  // heq
        if (RA.PrefU32() == RB.PrefU32()) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::HaltInsn, insn_pc, RA.PrefU32(), false, "heq triggered"};
        }
        return {};
    case 0x258:  // hgt
        if (RA.PrefS32() > RB.PrefS32()) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::HaltInsn, insn_pc, RA.PrefU32(), false, "hgt triggered"};
        }
        return {};
    case 0x2D8:  // hlgt
        if (RA.PrefU32() > RB.PrefU32()) {
            run_state_ = RunState::Halted;
            return StopInfo{StopReason::HaltInsn, insn_pc, RA.PrefU32(), false, "hlgt triggered"};
        }
        return {};

    // --- Single-Precision Floating-Point ---
    case 0x2C4:  // fa
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, PackSpuF32(FlushDenormF32(RA.U32(i)) + FlushDenormF32(RB.U32(i))));
        gpr_[rt_idx] = R; return {};
    case 0x2C5:  // fs
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, PackSpuF32(FlushDenormF32(RA.U32(i)) - FlushDenormF32(RB.U32(i))));
        gpr_[rt_idx] = R; return {};
    case 0x2C6:  // fm
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, PackSpuF32(FlushDenormF32(RA.U32(i)) * FlushDenormF32(RB.U32(i))));
        gpr_[rt_idx] = R; return {};
    case 0x1B8:  // frest
        for (size_t i = 0; i < 4; ++i) {
            const float a = FlushDenormF32(RA.U32(i));
            R.SetU32(i, a == 0.0f ? ((RA.U32(i) & 0x80000000u) | 0x7FFFFFFFu) : PackSpuF32(1.0f / a));
        }
        gpr_[rt_idx] = R; return {};
    case 0x1B9:  // frsqest
        for (size_t i = 0; i < 4; ++i) {
            const float a = std::fabs(FlushDenormF32(RA.U32(i)));
            R.SetU32(i, a == 0.0f ? 0x7FFFFFFFu : PackSpuF32(1.0f / std::sqrt(a)));
        }
        gpr_[rt_idx] = R; return {};
    case 0x3D4:  // fi (floating interpolate: returns refined estimate RB)
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, PackSpuF32(FlushDenormF32(RB.U32(i))));
        gpr_[rt_idx] = R; return {};
    case 0x3C2:  // fceq
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, FlushDenormF32(RA.U32(i)) == FlushDenormF32(RB.U32(i)) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x3CA:  // fcmeq
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, std::fabs(FlushDenormF32(RA.U32(i))) == std::fabs(FlushDenormF32(RB.U32(i))) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x2C2:  // fcgt
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, FlushDenormF32(RA.U32(i)) > FlushDenormF32(RB.U32(i)) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};
    case 0x2CA:  // fcmgt
        for (size_t i = 0; i < 4; ++i) R.SetU32(i, std::fabs(FlushDenormF32(RA.U32(i))) > std::fabs(FlushDenormF32(RB.U32(i))) ? 0xFFFFFFFFu : 0u);
        gpr_[rt_idx] = R; return {};

    // --- Double-Precision Floating-Point ---
    case 0x2CC:  // dfa
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(BitsToF64(RA.U64(i)) + BitsToF64(RB.U64(i))));
        gpr_[rt_idx] = R; return {};
    case 0x2CD:  // dfs
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(BitsToF64(RA.U64(i)) - BitsToF64(RB.U64(i))));
        gpr_[rt_idx] = R; return {};
    case 0x2CE:  // dfm
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(BitsToF64(RA.U64(i)) * BitsToF64(RB.U64(i))));
        gpr_[rt_idx] = R; return {};
    case 0x35C:  // dfma: A*B + T
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(BitsToF64(RA.U64(i)) * BitsToF64(RB.U64(i)) + BitsToF64(RT.U64(i))));
        gpr_[rt_idx] = R; return {};
    case 0x35D:  // dfms: A*B - T
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(BitsToF64(RA.U64(i)) * BitsToF64(RB.U64(i)) - BitsToF64(RT.U64(i))));
        gpr_[rt_idx] = R; return {};
    case 0x35E:  // dfnms: T - A*B
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(BitsToF64(RT.U64(i)) - BitsToF64(RA.U64(i)) * BitsToF64(RB.U64(i))));
        gpr_[rt_idx] = R; return {};
    case 0x35F:  // dfnma: -(A*B + T)
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, F64ToBits(-(BitsToF64(RA.U64(i)) * BitsToF64(RB.U64(i)) + BitsToF64(RT.U64(i)))));
        gpr_[rt_idx] = R; return {};
    case 0x3C3:  // dfceq
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, BitsToF64(RA.U64(i)) == BitsToF64(RB.U64(i)) ? ~0ULL : 0ULL);
        gpr_[rt_idx] = R; return {};
    case 0x3CB:  // dfcmeq
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, std::fabs(BitsToF64(RA.U64(i))) == std::fabs(BitsToF64(RB.U64(i))) ? ~0ULL : 0ULL);
        gpr_[rt_idx] = R; return {};
    case 0x2C3:  // dfcgt
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, BitsToF64(RA.U64(i)) > BitsToF64(RB.U64(i)) ? ~0ULL : 0ULL);
        gpr_[rt_idx] = R; return {};
    case 0x2CB:  // dfcmgt
        for (size_t i = 0; i < 2; ++i) R.SetU64(i, std::fabs(BitsToF64(RA.U64(i))) > std::fabs(BitsToF64(RB.U64(i))) ? ~0ULL : 0ULL);
        gpr_[rt_idx] = R; return {};
    case 0x3B8:  // fesd (even words 0,2 -> doubles 0,1)
        R.SetU64(0, F64ToBits(static_cast<double>(FlushDenormF32(RA.U32(0)))));
        R.SetU64(1, F64ToBits(static_cast<double>(FlushDenormF32(RA.U32(2)))));
        gpr_[rt_idx] = R; return {};
    case 0x3B9:  // frds (doubles 0,1 -> even words 0,2; odd words 1,3 zeroed)
        R.SetU32(0, F32ToBits(static_cast<float>(BitsToF64(RA.U64(0)))));
        R.SetU32(1, 0u);
        R.SetU32(2, F32ToBits(static_cast<float>(BitsToF64(RA.U64(1)))));
        R.SetU32(3, 0u);
        gpr_[rt_idx] = R; return {};
    case 0x3BF: {  // dftsv (7-bit mask: bit6=NaN, 5=+Inf, 4=-Inf, 3=+0, 2=-0, 1=+Denorm, 0=-Denorm)
        const uint32_t mask = rb_idx & 0x7Fu;
        for (size_t i = 0; i < 2; ++i) {
            const uint64_t bits = RA.U64(i);
            const bool neg = (bits >> 63) != 0;
            const uint64_t exp = (bits >> 52) & 0x7FFu;
            const uint64_t frac = bits & 0x000FFFFFFFFFFFFFULL;
            uint32_t cls = 0;
            if (exp == 0x7FFu) {
                if (frac != 0) cls = 0x40u;          // NaN
                else cls = neg ? 0x10u : 0x20u;      // -Inf / +Inf
            } else if (exp == 0) {
                if (frac == 0) cls = neg ? 0x04u : 0x08u;  // -0 / +0
                else cls = neg ? 0x01u : 0x02u;            // -Denorm / +Denorm
            }
            R.SetU64(i, (cls & mask) ? ~0ULL : 0ULL);
        }
        gpr_[rt_idx] = R; return {};
    }
    case 0x398:  // fscrrd
        gpr_[rt_idx] = fpscr_;
        return {};
    case 0x3BA:  // fscrwr
        fpscr_ = RA;
        return {};

    default:
        break;
    }

    char msgbuf[64];
    std::snprintf(msgbuf, sizeof(msgbuf), "Invalid SPU opcode 0x%08X at 0x%05X", w, insn_pc);
    return StopInfo{StopReason::InvalidInsn, insn_pc, w, false, msgbuf};
}

}  // namespace spu
