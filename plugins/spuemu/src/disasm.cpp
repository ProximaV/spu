#include "disasm.h"

#include "spu_channels.h"

#include <cstdio>

namespace spu {

namespace {

inline uint32_t Bits(uint32_t w, int lo, int hi) {
    return (w >> (31 - hi)) & ((1u << (hi - lo + 1)) - 1u);
}

inline int32_t Sext(uint32_t v, int bits) {
    const uint32_t sign = 1u << (bits - 1);
    return static_cast<int32_t>((v ^ sign) - sign);
}

std::string RegName(uint32_t r) {
    r &= 0x7Fu;
    if (r == 0) return "lr";
    if (r == 1) return "sp";
    char buf[16];
    std::snprintf(buf, sizeof(buf), "r%u", r);
    return buf;
}

std::string ChName(uint32_t ch) {
    ch &= 0x7Fu;
    if (const char *sym = ChannelSymbolicName(static_cast<uint8_t>(ch))) {
        return sym;
    }
    char buf[16];
    std::snprintf(buf, sizeof(buf), "ch%u", ch);
    return buf;
}

std::string FmtHexS(int32_t v) {
    char buf[32];
    if (v < 0) std::snprintf(buf, sizeof(buf), "-0x%X", static_cast<unsigned>(-v));
    else if (v < 10) std::snprintf(buf, sizeof(buf), "%d", v);
    else std::snprintf(buf, sizeof(buf), "0x%X", static_cast<unsigned>(v));
    return buf;
}

std::string FmtHexU(uint32_t v) {
    char buf[32];
    if (v < 10) std::snprintf(buf, sizeof(buf), "%u", v);
    else std::snprintf(buf, sizeof(buf), "0x%X", v);
    return buf;
}

std::string FmtAddr(uint32_t a) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%05X", a);
    return buf;
}

std::string BrSuffix(uint32_t rb) {
    if (rb & 0x20u) return "d";
    if (rb & 0x10u) return "e";
    return "";
}

}  // namespace

std::string DisassembleSpu(uint32_t pc, uint32_t w, uint32_t lslr) {
    const uint32_t rt = w & 0x7Fu;
    const uint32_t ra = (w >> 7) & 0x7Fu;
    const uint32_t rb = (w >> 14) & 0x7Fu;
    const uint32_t rc = (w >> 21) & 0x7Fu;  // For RRR: bits[4:10] = RT, bits[25:31] = RC

    // 1. 4-bit opcodes (RRR)
    const uint32_t op4 = w >> 28;
    const char *rrr_mn = nullptr;
    switch (op4) {
    case 0x8: rrr_mn = "selb"; break;
    case 0xB: rrr_mn = "shufb"; break;
    case 0xC: rrr_mn = "mpya"; break;
    case 0xD: rrr_mn = "fnms"; break;
    case 0xE: rrr_mn = "fma"; break;
    case 0xF: rrr_mn = "fms"; break;
    default: break;
    }
    if (rrr_mn) {
        // RRR bit layout: OP4[0:3] RT[4:10] RB[11:17] RA[18:24] RC[25:31]
        return std::string(rrr_mn) + " " + RegName(rc) + ", " + RegName(ra) + ", " +
               RegName(rb) + ", " + RegName(rt);
    }

    // 2. 7-bit opcodes (RI18 / HBRA / HBRR)
    const uint32_t op7 = w >> 25;
    if (op7 == 0x21) {
        const uint32_t i18 = Bits(w, 7, 24);
        return "ila " + RegName(rt) + ", " + FmtHexU(i18);
    }
    if (op7 == 0x08 || op7 == 0x09) {
        const uint32_t roh = Bits(w, 7, 8);
        const int32_t ro9 = Sext((roh << 7) | rt, 9);
        const int32_t i16 = Sext(Bits(w, 9, 24), 16);
        const uint32_t br_ea = (pc + static_cast<uint32_t>(ro9 << 2)) & lslr;
        const uint32_t targ = (op7 == 0x09)
                                  ? ((pc + static_cast<uint32_t>(i16 << 2)) & lslr)
                                  : (static_cast<uint32_t>(i16 << 2) & lslr);
        return std::string(op7 == 0x09 ? "hbrr " : "hbra ") + FmtAddr(br_ea) + ", " + FmtAddr(targ);
    }

    // 3. 8-bit opcodes (RI10)
    const uint32_t op8 = w >> 24;
    const int32_t i10s = Sext(Bits(w, 8, 17), 10);
    const uint32_t i10b8 = Bits(w, 8, 17) & 0xFFu;
    switch (op8) {
    case 0x04:
        if (i10s == 0) return "lr " + RegName(rt) + ", " + RegName(ra);
        return "ori " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x05: return "orhi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x06: return "orbi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexU(i10b8);
    case 0x0C: return "sfi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x0D: return "sfhi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x14: return "andi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x15: return "andhi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x16: return "andbi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexU(i10b8);
    case 0x1C: return "ai " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x1D: return "ahi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x24: return "stqd " + RegName(rt) + ", " + FmtHexS(i10s << 4) + "(" + RegName(ra) + ")";
    case 0x34: return "lqd " + RegName(rt) + ", " + FmtHexS(i10s << 4) + "(" + RegName(ra) + ")";
    case 0x44: return "xori " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x45: return "xorhi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x46: return "xorbi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexU(i10b8);
    case 0x4C: return "cgti " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x4D: return "cgthi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x4E: return "cgtbi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(Sext(i10b8, 8));
    case 0x4F: return "hgti " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x5C: return "clgti " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x5D: return "clgthi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x5E: return "clgtbi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexU(i10b8);
    case 0x5F: return "hlgti " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x74: return "mpyi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x75: return "mpyui " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x7C: return "ceqi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x7D: return "ceqhi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i10s);
    case 0x7E: return "ceqbi " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexU(i10b8);
    case 0x7F: return "heqi " + RegName(ra) + ", " + FmtHexS(i10s);
    default: break;
    }

    // 4. 9-bit opcodes (RI16)
    const uint32_t op9 = w >> 23;
    const uint32_t i16u = Bits(w, 9, 24);
    const int32_t i16s = Sext(i16u, 16);
    const uint32_t abs_a = static_cast<uint32_t>(i16s << 2) & lslr;
    const uint32_t rel_a = (pc + static_cast<uint32_t>(i16s << 2)) & lslr;
    switch (op9) {
    case 0x040: return "brz " + RegName(rt) + ", " + FmtAddr(rel_a);
    case 0x041: return "stqa " + RegName(rt) + ", " + FmtAddr(abs_a & ~15u);
    case 0x042: return "brnz " + RegName(rt) + ", " + FmtAddr(rel_a);
    case 0x044: return "brhz " + RegName(rt) + ", " + FmtAddr(rel_a);
    case 0x046: return "brhnz " + RegName(rt) + ", " + FmtAddr(rel_a);
    case 0x047: return "stqr " + RegName(rt) + ", " + FmtAddr(rel_a & ~15u);
    case 0x060: return "bra " + FmtAddr(abs_a);
    case 0x061: return "lqa " + RegName(rt) + ", " + FmtAddr(abs_a & ~15u);
    case 0x062: return "brasl " + RegName(rt) + ", " + FmtAddr(abs_a);
    case 0x064: return "br " + FmtAddr(rel_a);
    case 0x065: return "fsmbi " + RegName(rt) + ", " + FmtHexU(i16u);
    case 0x066: return "brsl " + RegName(rt) + ", " + FmtAddr(rel_a);
    case 0x067: return "lqr " + RegName(rt) + ", " + FmtAddr(rel_a & ~15u);
    case 0x081: return "il " + RegName(rt) + ", " + FmtHexS(i16s);
    case 0x082: return "ilhu " + RegName(rt) + ", " + FmtHexU(i16u);
    case 0x083: return "ilh " + RegName(rt) + ", " + FmtHexU(i16u);
    case 0x0C1: return "iohl " + RegName(rt) + ", " + FmtHexU(i16u);
    default: break;
    }

    // 5. 10-bit opcodes (RI8 float conversions)
    const uint32_t op10 = w >> 22;
    const uint32_t i8 = Bits(w, 10, 17);
    if (op10 >= 0x1D8 && op10 <= 0x1DB) {
        const char *mns[4] = { "cflts", "cfltu", "csflt", "cuflt" };
        const int bias = (op10 <= 0x1D9) ? 173 : 155;
        const int scale = bias - static_cast<int>(i8);
        return std::string(mns[op10 - 0x1D8]) + " " + RegName(rt) + ", " + RegName(ra) + ", " + std::to_string(scale);
    }

    // 6. 11-bit opcodes
    const uint32_t op11 = w >> 21;
    const int32_t i7s = Sext(rb, 7);
    auto rr = [&](const char *m) {
        return std::string(m) + " " + RegName(rt) + ", " + RegName(ra) + ", " + RegName(rb);
    };
    auto r1 = [&](const char *m) {
        return std::string(m) + " " + RegName(rt) + ", " + RegName(ra);
    };
    auto ri7 = [&](const char *m) {
        return std::string(m) + " " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexS(i7s);
    };

    switch (op11) {
    case 0x000: return "stop " + FmtHexU(w & 0x3FFFu);
    case 0x001: return "lnop";
    case 0x002: return ((w >> 20) & 1u) ? "syncc" : "sync";
    case 0x003: return "dsync";
    case 0x00C: return "mfspr " + RegName(rt) + ", sa" + std::to_string(ra);
    case 0x00D: return "rdch " + RegName(rt) + ", " + ChName(ra);
    case 0x00F: return "rchcnt " + RegName(rt) + ", " + ChName(ra);
    case 0x040: return rr("sf");
    case 0x041: return rr("or");
    case 0x042: return rr("bg");
    case 0x048: return rr("sfh");
    case 0x049: return rr("nor");
    case 0x053: return rr("absdb");
    case 0x058: return rr("rot");
    case 0x059: return rr("rotm");
    case 0x05A: return rr("rotma");
    case 0x05B: return rr("shl");
    case 0x05C: return rr("roth");
    case 0x05D: return rr("rothm");
    case 0x05E: return rr("rotmah");
    case 0x05F: return rr("shlh");
    case 0x078: return ri7("roti");
    case 0x079: return ri7("rotmi");
    case 0x07A: return ri7("rotmai");
    case 0x07B: return ri7("shli");
    case 0x07C: return ri7("rothi");
    case 0x07D: return ri7("rothmi");
    case 0x07E: return ri7("rotmahi");
    case 0x07F: return ri7("shlhi");
    case 0x0C0: return rr("a");
    case 0x0C1: return rr("and");
    case 0x0C2: return rr("cg");
    case 0x0C8: return rr("ah");
    case 0x0C9: return rr("nand");
    case 0x0D3: return rr("avgb");
    case 0x10C: return "mtspr sa" + std::to_string(ra) + ", " + RegName(rt);
    case 0x10D: return "wrch " + ChName(ra) + ", " + RegName(rt);
    case 0x128: return "biz" + BrSuffix(rb) + " " + RegName(rt) + ", " + RegName(ra);
    case 0x129: return "binz" + BrSuffix(rb) + " " + RegName(rt) + ", " + RegName(ra);
    case 0x12A: return "bihz" + BrSuffix(rb) + " " + RegName(rt) + ", " + RegName(ra);
    case 0x12B: return "bihnz" + BrSuffix(rb) + " " + RegName(rt) + ", " + RegName(ra);
    case 0x140: return "stopd " + RegName(ra) + ", " + RegName(rb) + ", " + RegName(rt);
    case 0x144: return rr("stqx");
    case 0x1A8: return "bi" + BrSuffix(rb) + " " + RegName(ra);
    case 0x1A9: return "bisl" + BrSuffix(rb) + " " + RegName(rt) + ", " + RegName(ra);
    case 0x1AA: return "iret" + BrSuffix(rb);
    case 0x1AB: return "bisled" + BrSuffix(rb) + " " + RegName(rt) + ", " + RegName(ra);
    case 0x1AC: {
        if (rb & 0x40u) return "hbrp";
        const int32_t ro9 = Sext(((rb & 3u) << 7) | rt, 9);
        const uint32_t br_ea = (pc + static_cast<uint32_t>(ro9 << 2)) & lslr;
        return "hbr " + FmtAddr(br_ea) + ", " + RegName(ra);
    }
    case 0x1B0: return r1("gb");
    case 0x1B1: return r1("gbh");
    case 0x1B2: return r1("gbb");
    case 0x1B4: return r1("fsm");
    case 0x1B5: return r1("fsmh");
    case 0x1B6: return r1("fsmb");
    case 0x1B8: return r1("frest");
    case 0x1B9: return r1("frsqest");
    case 0x1C4: return rr("lqx");
    case 0x1CC: return rr("rotqbybi");
    case 0x1CD: return rr("rotqmbybi");
    case 0x1CF: return rr("shlqbybi");
    case 0x1D4: return rr("cbx");
    case 0x1D5: return rr("chx");
    case 0x1D6: return rr("cwx");
    case 0x1D7: return rr("cdx");
    case 0x1D8: return rr("rotqbi");
    case 0x1D9: return rr("rotqmbi");
    case 0x1DB: return rr("shlqbi");
    case 0x1DC: return rr("rotqby");
    case 0x1DD: return rr("rotqmby");
    case 0x1DF: return rr("shlqby");
    case 0x1F0: return r1("orx");
    case 0x1F4: return "cbd " + RegName(rt) + ", " + FmtHexS(i7s) + "(" + RegName(ra) + ")";
    case 0x1F5: return "chd " + RegName(rt) + ", " + FmtHexS(i7s) + "(" + RegName(ra) + ")";
    case 0x1F6: return "cwd " + RegName(rt) + ", " + FmtHexS(i7s) + "(" + RegName(ra) + ")";
    case 0x1F7: return "cdd " + RegName(rt) + ", " + FmtHexS(i7s) + "(" + RegName(ra) + ")";
    case 0x1F8: return ri7("rotqbii");
    case 0x1F9: return ri7("rotqmbii");
    case 0x1FB: return ri7("shlqbii");
    case 0x1FC: return ri7("rotqbyi");
    case 0x1FD: return ri7("rotqmbyi");
    case 0x1FF:
        if (i7s == 0) return "lr " + RegName(rt) + ", " + RegName(ra);
        return ri7("shlqbyi");
    case 0x201: return (rt != 0) ? ("nop " + RegName(rt)) : "nop";
    case 0x240: return rr("cgt");
    case 0x241: return rr("xor");
    case 0x248: return rr("cgth");
    case 0x249: return rr("eqv");
    case 0x250: return rr("cgtb");
    case 0x253: return rr("sumb");
    case 0x258: return "hgt " + RegName(ra) + ", " + RegName(rb);
    case 0x2A5: return r1("clz");
    case 0x2A6: return r1("xswd");
    case 0x2AE: return r1("xshw");
    case 0x2B4: return r1("cntb");
    case 0x2B6: return r1("xsbh");
    case 0x2C0: return rr("clgt");
    case 0x2C1: return rr("andc");
    case 0x2C2: return rr("fcgt");
    case 0x2C3: return rr("dfcgt");
    case 0x2C4: return rr("fa");
    case 0x2C5: return rr("fs");
    case 0x2C6: return rr("fm");
    case 0x2C8: return rr("clgth");
    case 0x2C9: return rr("orc");
    case 0x2CA: return rr("fcmgt");
    case 0x2CB: return rr("dfcmgt");
    case 0x2CC: return rr("dfa");
    case 0x2CD: return rr("dfs");
    case 0x2CE: return rr("dfm");
    case 0x2D0: return rr("clgtb");
    case 0x2D8: return "hlgt " + RegName(ra) + ", " + RegName(rb);
    case 0x340: return rr("addx");
    case 0x341: return rr("sfx");
    case 0x342: return rr("cgx");
    case 0x343: return rr("bgx");
    case 0x346: return rr("mpyhha");
    case 0x34E: return rr("mpyhhau");
    case 0x35C: return rr("dfma");
    case 0x35D: return rr("dfms");
    case 0x35E: return rr("dfnms");
    case 0x35F: return rr("dfnma");
    case 0x398: return "fscrrd " + RegName(rt);
    case 0x3B8: return r1("fesd");
    case 0x3B9: return r1("frds");
    case 0x3BA: return "fscrwr " + RegName(ra);
    case 0x3BF: return "dftsv " + RegName(rt) + ", " + RegName(ra) + ", " + FmtHexU(rb);
    case 0x3C0: return rr("ceq");
    case 0x3C2: return rr("fceq");
    case 0x3C3: return rr("dfceq");
    case 0x3C4: return rr("mpy");
    case 0x3C5: return rr("mpyh");
    case 0x3C6: return rr("mpyhh");
    case 0x3C7: return rr("mpys");
    case 0x3C8: return rr("ceqh");
    case 0x3CA: return rr("fcmeq");
    case 0x3CB: return rr("dfcmeq");
    case 0x3CC: return rr("mpyu");
    case 0x3CE: return rr("mpyhhu");
    case 0x3D0: return rr("ceqb");
    case 0x3D4: return rr("fi");
    case 0x3D8: return "heq " + RegName(ra) + ", " + RegName(rb);
    default: break;
    }

    char buf[32];
    std::snprintf(buf, sizeof(buf), ".long 0x%08X", w);
    return buf;
}

}  // namespace spu
