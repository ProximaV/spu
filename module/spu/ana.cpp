#include "spu.hpp"

// IBM big-endian bit numbering: bit 0 is MSB (1<<31), bit 31 is LSB (1<<0).
static inline uint32 ibits(uint32 word, int hi, int lo)
{
    int shift = 31 - lo;
    int width = lo - hi + 1;
    return (word >> shift) & ((1u << width) - 1u);
}

static inline int32 sign_extend(uint32 val, int bits)
{
    uint32 mask = 1u << (bits - 1);
    val &= (1u << bits) - 1u;
    return static_cast<int32>((val ^ mask) - mask);
}

enum spu_fmt_t : uint8
{
    FMT_NONE = 0,
    FMT_RR,         // rt, ra, rb
    FMT_R,          // rt, ra
    FMT_R_NO_RA,    // rt (fscrrd)
    FMT_FSCRWR,     // ra (RT is false target)
    FMT_HALT_RR,    // ra, rb (RT is false target: heq, hgt, hlgt)
    FMT_HALT_RI10,  // ra, imm10s (RT is false target: heqi, hgti, hlgti)
    FMT_SPR_RD,     // rt, sa (mfspr)
    FMT_SPR_WR,     // sa, rt (mtspr)
    FMT_CH_RD,      // rt, ca (rdch, rchcnt)
    FMT_CH_WR,      // ca, rt (wrch)
    FMT_NOOPS,      // lnop, dsync
    FMT_NOP,        // nop [rt false target]
    FMT_SYNC,       // sync / syncc
    FMT_STOP,       // stop type14 (reserved bits 11:17 must be 0)
    FMT_STOPD,      // stopd [ra, rb, rc]
    FMT_RRR,        // rt, ra, rb, rc
    FMT_BR_IND_1,   // bi ra (D/E bits)
    FMT_IRET,       // iret [ra] (D/E bits; PC <- SRR0)
    FMT_BR_IND_2,   // bisl, bisled, biz, binz, bihz, bihnz rt, ra (D/E bits)
    FMT_HBR,        // hbr brinst, ra (or hbrp)
    FMT_HBRA,       // hbra brinst, abs_brtarg (9-bit RO, 16-bit abs)
    FMT_HBRR,       // hbrr brinst, rel_brtarg (9-bit RO, 16-bit rel)
    FMT_RI7_S,      // rt, ra, i7s (shifts/rotates)
    FMT_RI7_U,      // rt, ra, i7u (dftsv)
    FMT_RI7_LS,     // cbd, chd, cwd, cdd: rt, i7s(ra)
    FMT_RI8_FLT,    // cflts, cfltu (bias 173), csflt, cuflt (bias 155)
    FMT_RI10_S,     // rt, ra, i10s
    FMT_RI10_B8U,   // rt, ra, i10 & 0xFF (andbi, orbi, xorbi, ceqbi, clgtbi)
    FMT_RI10_B8S,   // rt, ra, sext8(i10 & 0xFF) (cgtbi)
    FMT_RI10_LS,    // lqd, stqd: rt, (i10s<<4)(ra)
    FMT_RI16_U,     // fsmbi, ilh, ilhu, iohl: rt, i16u
    FMT_RI16_S,     // il: rt, i16s
    FMT_RI16_BR_R,  // br: rel16 (no RT)
    FMT_RI16_BR_A,  // bra: abs16 (no RT)
    FMT_RI16_CBR_R, // brz, brnz, brhz, brhnz, brsl: rt, rel16
    FMT_RI16_CBR_A, // brasl: rt, abs16
    FMT_RI16_LS_A,  // lqa, stqa: rt, abs16 & ~0xF
    FMT_RI16_LS_R,  // lqr, stqr: rt, rel16 & ~0xF
    FMT_RI18,       // ila: rt, i18u
};

struct spu_desc_t
{
    uint16 itype;
    spu_fmt_t fmt;
    uint16 extra;   // dtype for cbd..cdd, bias for RI8 float converts
};

static spu_desc_t g_itable[2048];
static bool g_itable_inited = false;

static void fill_range(uint32 opcode, int opbits, uint16 itype, spu_fmt_t fmt, uint16 extra = 0)
{
    int shift = 11 - opbits;
    uint32 count = 1u << shift;
    uint32 base = opcode << shift;
    for (uint32 i = 0; i < count; ++i)
    {
        g_itable[base + i] = { itype, fmt, extra };
    }
}

static void init_itable()
{
    if (g_itable_inited)
        return;
    memset(g_itable, 0, sizeof(g_itable));

    // --- 4-bit opcodes (RRR, bits 0:3) ---
    fill_range(0x8, 4, SPU_selb,    FMT_RRR);
    fill_range(0xB, 4, SPU_shufb,   FMT_RRR);
    fill_range(0xC, 4, SPU_mpya,    FMT_RRR);
    fill_range(0xD, 4, SPU_fnms,    FMT_RRR);
    fill_range(0xE, 4, SPU_fma,     FMT_RRR);
    fill_range(0xF, 4, SPU_fms,     FMT_RRR);

    // --- 7-bit opcodes (RI18 / I16RO, bits 0:6) ---
    fill_range(0x08, 7, SPU_hbra,   FMT_HBRA);
    fill_range(0x09, 7, SPU_hbrr,   FMT_HBRR);
    fill_range(0x21, 7, SPU_ila,    FMT_RI18);

    // --- 8-bit opcodes (RI10, bits 0:7) ---
    fill_range(0x04, 8, SPU_ori,    FMT_RI10_S);
    fill_range(0x05, 8, SPU_orhi,   FMT_RI10_S);
    fill_range(0x06, 8, SPU_orbi,   FMT_RI10_B8U);
    fill_range(0x0C, 8, SPU_sfi,    FMT_RI10_S);
    fill_range(0x0D, 8, SPU_sfhi,   FMT_RI10_S);
    fill_range(0x14, 8, SPU_andi,   FMT_RI10_S);
    fill_range(0x15, 8, SPU_andhi,  FMT_RI10_S);
    fill_range(0x16, 8, SPU_andbi,  FMT_RI10_B8U);
    fill_range(0x1C, 8, SPU_ai,     FMT_RI10_S);
    fill_range(0x1D, 8, SPU_ahi,    FMT_RI10_S);
    fill_range(0x24, 8, SPU_stqd,   FMT_RI10_LS);
    fill_range(0x34, 8, SPU_lqd,    FMT_RI10_LS);
    fill_range(0x44, 8, SPU_xori,   FMT_RI10_S);
    fill_range(0x45, 8, SPU_xorhi,  FMT_RI10_S);
    fill_range(0x46, 8, SPU_xorbi,  FMT_RI10_B8U);
    fill_range(0x4C, 8, SPU_cgti,   FMT_RI10_S);
    fill_range(0x4D, 8, SPU_cgthi,  FMT_RI10_S);
    fill_range(0x4E, 8, SPU_cgtbi,  FMT_RI10_B8S);
    fill_range(0x4F, 8, SPU_hgti,   FMT_HALT_RI10);
    fill_range(0x5C, 8, SPU_clgti,  FMT_RI10_S);
    fill_range(0x5D, 8, SPU_clgthi, FMT_RI10_S);
    fill_range(0x5E, 8, SPU_clgtbi, FMT_RI10_B8U);
    fill_range(0x5F, 8, SPU_hlgti,  FMT_HALT_RI10);
    fill_range(0x74, 8, SPU_mpyi,   FMT_RI10_S);
    fill_range(0x75, 8, SPU_mpyui,  FMT_RI10_S);
    fill_range(0x7C, 8, SPU_ceqi,   FMT_RI10_S);
    fill_range(0x7D, 8, SPU_ceqhi,  FMT_RI10_S);
    fill_range(0x7E, 8, SPU_ceqbi,  FMT_RI10_B8U);
    fill_range(0x7F, 8, SPU_heqi,   FMT_HALT_RI10);

    // --- 9-bit opcodes (RI16, bits 0:8) ---
    fill_range(0x040, 9, SPU_brz,   FMT_RI16_CBR_R);
    fill_range(0x041, 9, SPU_stqa,  FMT_RI16_LS_A);
    fill_range(0x042, 9, SPU_brnz,  FMT_RI16_CBR_R);
    fill_range(0x044, 9, SPU_brhz,  FMT_RI16_CBR_R);
    fill_range(0x046, 9, SPU_brhnz, FMT_RI16_CBR_R);
    fill_range(0x047, 9, SPU_stqr,  FMT_RI16_LS_R);
    fill_range(0x060, 9, SPU_bra,   FMT_RI16_BR_A);
    fill_range(0x061, 9, SPU_lqa,   FMT_RI16_LS_A);
    fill_range(0x062, 9, SPU_brasl, FMT_RI16_CBR_A);
    fill_range(0x064, 9, SPU_br,    FMT_RI16_BR_R);
    fill_range(0x065, 9, SPU_fsmbi, FMT_RI16_U);
    fill_range(0x066, 9, SPU_brsl,  FMT_RI16_CBR_R);
    fill_range(0x067, 9, SPU_lqr,   FMT_RI16_LS_R);
    fill_range(0x081, 9, SPU_il,    FMT_RI16_S);
    fill_range(0x082, 9, SPU_ilhu,  FMT_RI16_U);
    fill_range(0x083, 9, SPU_ilh,   FMT_RI16_U);
    fill_range(0x0C1, 9, SPU_iohl,  FMT_RI16_U);

    // --- 10-bit opcodes (RI8 float conversions, bits 0:9) ---
    fill_range(0x1D8, 10, SPU_cflts, FMT_RI8_FLT, 173);
    fill_range(0x1D9, 10, SPU_cfltu, FMT_RI8_FLT, 173);
    fill_range(0x1DA, 10, SPU_csflt, FMT_RI8_FLT, 155);
    fill_range(0x1DB, 10, SPU_cuflt, FMT_RI8_FLT, 155);

    // --- 11-bit opcodes (RR / RI7 / Control / Channel, bits 0:10) ---
    fill_range(0x000, 11, SPU_stop,      FMT_STOP);
    fill_range(0x001, 11, SPU_lnop,      FMT_NOOPS);
    fill_range(0x002, 11, SPU_sync,      FMT_SYNC);
    fill_range(0x003, 11, SPU_dsync,     FMT_NOOPS);
    fill_range(0x00C, 11, SPU_mfspr,     FMT_SPR_RD);
    fill_range(0x00D, 11, SPU_rdch,      FMT_CH_RD);
    fill_range(0x00F, 11, SPU_rchcnt,    FMT_CH_RD);
    fill_range(0x040, 11, SPU_sf,        FMT_RR);
    fill_range(0x041, 11, SPU_or,        FMT_RR);
    fill_range(0x042, 11, SPU_bg,        FMT_RR);
    fill_range(0x048, 11, SPU_sfh,       FMT_RR);
    fill_range(0x049, 11, SPU_nor,       FMT_RR);
    fill_range(0x053, 11, SPU_absdb,     FMT_RR);
    fill_range(0x058, 11, SPU_rot,       FMT_RR);
    fill_range(0x059, 11, SPU_rotm,      FMT_RR);
    fill_range(0x05A, 11, SPU_rotma,     FMT_RR);
    fill_range(0x05B, 11, SPU_shl,       FMT_RR);
    fill_range(0x05C, 11, SPU_roth,      FMT_RR);
    fill_range(0x05D, 11, SPU_rothm,     FMT_RR);
    fill_range(0x05E, 11, SPU_rotmah,    FMT_RR);
    fill_range(0x05F, 11, SPU_shlh,      FMT_RR);
    // RI7 shift/rotate immediates (NOTE: 0x07F shlhi FIXED from RR to RI7!)
    fill_range(0x078, 11, SPU_roti,      FMT_RI7_S);
    fill_range(0x079, 11, SPU_rotmi,     FMT_RI7_S);
    fill_range(0x07A, 11, SPU_rotmai,    FMT_RI7_S);
    fill_range(0x07B, 11, SPU_shli,      FMT_RI7_S);
    fill_range(0x07C, 11, SPU_rothi,     FMT_RI7_S);
    fill_range(0x07D, 11, SPU_rothmi,    FMT_RI7_S);
    fill_range(0x07E, 11, SPU_rotmahi,   FMT_RI7_S);
    fill_range(0x07F, 11, SPU_shlhi,     FMT_RI7_S);
    fill_range(0x0C0, 11, SPU_a,         FMT_RR);
    fill_range(0x0C1, 11, SPU_and,       FMT_RR);
    fill_range(0x0C2, 11, SPU_cg,        FMT_RR);
    fill_range(0x0C8, 11, SPU_ah,        FMT_RR);
    fill_range(0x0C9, 11, SPU_nand,      FMT_RR);
    fill_range(0x0D3, 11, SPU_avgb,      FMT_RR);
    fill_range(0x10C, 11, SPU_mtspr,     FMT_SPR_WR);
    fill_range(0x10D, 11, SPU_wrch,      FMT_CH_WR);
    fill_range(0x128, 11, SPU_biz,       FMT_BR_IND_2);
    fill_range(0x129, 11, SPU_binz,      FMT_BR_IND_2);
    fill_range(0x12A, 11, SPU_bihz,      FMT_BR_IND_2);
    fill_range(0x12B, 11, SPU_bihnz,     FMT_BR_IND_2);
    fill_range(0x140, 11, SPU_stopd,     FMT_STOPD);
    fill_range(0x144, 11, SPU_stqx,      FMT_RR);
    fill_range(0x1A8, 11, SPU_bi,        FMT_BR_IND_1);
    fill_range(0x1A9, 11, SPU_bisl,      FMT_BR_IND_2);
    fill_range(0x1AA, 11, SPU_iret,      FMT_IRET);
    fill_range(0x1AB, 11, SPU_bisled,    FMT_BR_IND_2);
    fill_range(0x1AC, 11, SPU_hbr,       FMT_HBR);
    fill_range(0x1B0, 11, SPU_gb,        FMT_R);
    fill_range(0x1B1, 11, SPU_gbh,       FMT_R);
    fill_range(0x1B2, 11, SPU_gbb,       FMT_R);
    fill_range(0x1B4, 11, SPU_fsm,       FMT_R);
    fill_range(0x1B5, 11, SPU_fsmh,      FMT_R);
    fill_range(0x1B6, 11, SPU_fsmb,      FMT_R);
    fill_range(0x1B8, 11, SPU_frest,     FMT_R);
    fill_range(0x1B9, 11, SPU_frsqest,   FMT_R);
    fill_range(0x1C4, 11, SPU_lqx,       FMT_RR);
    fill_range(0x1CC, 11, SPU_rotqbybi,  FMT_RR);
    fill_range(0x1CD, 11, SPU_rotqmbybi, FMT_RR);
    fill_range(0x1CF, 11, SPU_shlqbybi,  FMT_RR);
    fill_range(0x1D4, 11, SPU_cbx,       FMT_RR);
    fill_range(0x1D5, 11, SPU_chx,       FMT_RR);
    fill_range(0x1D6, 11, SPU_cwx,       FMT_RR);
    fill_range(0x1D7, 11, SPU_cdx,       FMT_RR);
    fill_range(0x1D8, 11, SPU_rotqbi,    FMT_RR);
    fill_range(0x1D9, 11, SPU_rotqmbi,   FMT_RR);
    fill_range(0x1DB, 11, SPU_shlqbi,    FMT_RR);
    fill_range(0x1DC, 11, SPU_rotqby,    FMT_RR);
    fill_range(0x1DD, 11, SPU_rotqmby,   FMT_RR);
    fill_range(0x1DF, 11, SPU_shlqby,    FMT_RR);
    fill_range(0x1F0, 11, SPU_orx,       FMT_R);
    fill_range(0x1F4, 11, SPU_cbd,       FMT_RI7_LS, dt_byte);
    fill_range(0x1F5, 11, SPU_chd,       FMT_RI7_LS, dt_word);
    fill_range(0x1F6, 11, SPU_cwd,       FMT_RI7_LS, dt_dword);
    fill_range(0x1F7, 11, SPU_cdd,       FMT_RI7_LS, dt_qword);
    fill_range(0x1F8, 11, SPU_rotqbii,   FMT_RI7_S);
    fill_range(0x1F9, 11, SPU_rotqmbii,  FMT_RI7_S);
    fill_range(0x1FB, 11, SPU_shlqbii,   FMT_RI7_S);
    fill_range(0x1FC, 11, SPU_rotqbyi,   FMT_RI7_S);
    fill_range(0x1FD, 11, SPU_rotqmbyi,  FMT_RI7_S);
    fill_range(0x1FF, 11, SPU_shlqbyi,   FMT_RI7_S);
    fill_range(0x201, 11, SPU_nop,       FMT_NOP);
    fill_range(0x240, 11, SPU_cgt,       FMT_RR);
    fill_range(0x241, 11, SPU_xor,       FMT_RR);
    fill_range(0x248, 11, SPU_cgth,      FMT_RR);
    fill_range(0x249, 11, SPU_eqv,       FMT_RR);
    fill_range(0x250, 11, SPU_cgtb,      FMT_RR);
    fill_range(0x253, 11, SPU_sumb,      FMT_RR);
    fill_range(0x258, 11, SPU_hgt,       FMT_HALT_RR);
    fill_range(0x2A5, 11, SPU_clz,       FMT_R);
    fill_range(0x2A6, 11, SPU_xswd,      FMT_R);
    fill_range(0x2AE, 11, SPU_xshw,      FMT_R);
    fill_range(0x2B4, 11, SPU_cntb,      FMT_R);
    fill_range(0x2B6, 11, SPU_xsbh,      FMT_R);
    fill_range(0x2C0, 11, SPU_clgt,      FMT_RR);
    fill_range(0x2C1, 11, SPU_andc,      FMT_RR);
    fill_range(0x2C2, 11, SPU_fcgt,      FMT_RR);
    fill_range(0x2C3, 11, SPU_dfcgt,     FMT_RR);
    fill_range(0x2C4, 11, SPU_fa,        FMT_RR);
    fill_range(0x2C5, 11, SPU_fs,        FMT_RR);
    fill_range(0x2C6, 11, SPU_fm,        FMT_RR);
    fill_range(0x2C8, 11, SPU_clgth,     FMT_RR);
    fill_range(0x2C9, 11, SPU_orc,       FMT_RR);
    fill_range(0x2CA, 11, SPU_fcmgt,     FMT_RR);
    fill_range(0x2CB, 11, SPU_dfcmgt,    FMT_RR);
    fill_range(0x2CC, 11, SPU_dfa,       FMT_RR);
    fill_range(0x2CD, 11, SPU_dfs,       FMT_RR);
    fill_range(0x2CE, 11, SPU_dfm,       FMT_RR);
    fill_range(0x2D0, 11, SPU_clgtb,     FMT_RR);
    fill_range(0x2D8, 11, SPU_hlgt,      FMT_HALT_RR);
    fill_range(0x340, 11, SPU_addx,      FMT_RR);
    fill_range(0x341, 11, SPU_sfx,       FMT_RR);
    fill_range(0x342, 11, SPU_cgx,       FMT_RR);
    fill_range(0x343, 11, SPU_bgx,       FMT_RR);
    fill_range(0x346, 11, SPU_mpyhha,    FMT_RR);
    fill_range(0x34E, 11, SPU_mpyhhau,   FMT_RR);
    fill_range(0x35C, 11, SPU_dfma,      FMT_RR);
    fill_range(0x35D, 11, SPU_dfms,      FMT_RR);
    fill_range(0x35E, 11, SPU_dfnms,     FMT_RR);
    fill_range(0x35F, 11, SPU_dfnma,     FMT_RR);
    fill_range(0x398, 11, SPU_fscrrd,    FMT_R_NO_RA);
    fill_range(0x3B8, 11, SPU_fesd,      FMT_R);
    fill_range(0x3B9, 11, SPU_frds,      FMT_R);
    fill_range(0x3BA, 11, SPU_fscrwr,    FMT_FSCRWR);
    fill_range(0x3BF, 11, SPU_dftsv,     FMT_RI7_U);
    fill_range(0x3C0, 11, SPU_ceq,       FMT_RR);
    fill_range(0x3C2, 11, SPU_fceq,      FMT_RR);
    fill_range(0x3C3, 11, SPU_dfceq,     FMT_RR);
    fill_range(0x3C4, 11, SPU_mpy,       FMT_RR);
    fill_range(0x3C5, 11, SPU_mpyh,      FMT_RR);
    fill_range(0x3C6, 11, SPU_mpyhh,     FMT_RR);
    fill_range(0x3C7, 11, SPU_mpys,      FMT_RR);
    fill_range(0x3C8, 11, SPU_ceqh,      FMT_RR);
    fill_range(0x3CA, 11, SPU_fcmeq,     FMT_RR);
    fill_range(0x3CB, 11, SPU_dfcmeq,    FMT_RR);
    fill_range(0x3CC, 11, SPU_mpyu,      FMT_RR);
    fill_range(0x3CE, 11, SPU_mpyhhu,    FMT_RR);
    fill_range(0x3D0, 11, SPU_ceqb,      FMT_RR);
    fill_range(0x3D4, 11, SPU_fi,        FMT_RR);
    fill_range(0x3D8, 11, SPU_heq,       FMT_HALT_RR);

    g_itable_inited = true;
}

ea_t spu_t::wrap_ls_addr(ea_t base_ea, sval_t target, bool quadword_align) const
{
    uint32 mask = lslr ? lslr : SPU_DEFAULT_LSLR;
    // Support multi-overlay SPU ELFs mapped above 0x40000: preserve high base bits if base_ea > mask.
    ea_t overlay_base = (base_ea > mask) ? (base_ea & ~ea_t(mask)) : 0;
    uint32 wrapped = static_cast<uint32>(target) & mask;
    if (quadword_align)
        wrapped &= ~0xFu;
    else
        wrapped &= ~0x3u;
    return overlay_base | wrapped;
}

static void set_reg(op_t &op, uint16 reg, op_dtype_t dtype = dt_byte16)
{
    op.type = o_reg;
    op.reg = reg;
    op.dtype = dtype;
}

static void set_imm(op_t &op, uval_t val, bool is_signed, op_dtype_t dtype = dt_dword)
{
    op.type = o_imm;
    op.value = val;
    op.dtype = dtype;
    if (is_signed)
        op.specval |= SPU_OP_SIGNED;
}

int spu_t::spu_ana(insn_t *insn)
{
    init_itable();

    // SPU ISA v1.2 Sec. 2.3 (p. 28): Instructions must be 4-byte word aligned.
    if ((insn->ea & 3) != 0)
        return 0;

    uint32 opcode = insn->get_next_dword();
    const spu_desc_t &d = g_itable[ibits(opcode, 0, 10)];
    if (d.itype == SPU_null)
        return 0;

    insn->itype = d.itype;
    insn->auxpref = 0;
    insn->segpref = 0;

    uint16 rb = static_cast<uint16>(ibits(opcode, 11, 17));
    uint16 ra = static_cast<uint16>(ibits(opcode, 18, 24));
    uint16 rt = static_cast<uint16>(ibits(opcode, 25, 31));

    switch (d.fmt)
    {
    case FMT_RR:
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_reg(insn->Op3, rb);
        break;

    case FMT_R:
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        break;

    case FMT_R_NO_RA:
        // fscrrd rt (bits 11:24 reserved)
        set_reg(insn->Op1, rt);
        break;

    case FMT_FSCRWR:
        // fscrwr ra (p. 235: RT is false target, omitted from official syntax)
        set_reg(insn->Op1, ra);
        insn->segpref = static_cast<uchar>(rt);
        break;

    case FMT_HALT_RR:
        // heq/hgt/hlgt ra, rb (pp. 150, 152, 154: RT is false target, omitted)
        set_reg(insn->Op1, ra);
        set_reg(insn->Op2, rb);
        insn->segpref = static_cast<uchar>(rt);
        break;

    case FMT_HALT_RI10:
    {
        // heqi/hgti/hlgti ra, imm10s (pp. 151, 153, 155: RT is false target, omitted)
        int32 i10 = sign_extend(ibits(opcode, 8, 17), 10);
        set_reg(insn->Op1, ra);
        set_imm(insn->Op2, static_cast<uval_t>(static_cast<sval_t>(i10)), i10 < 0);
        insn->segpref = static_cast<uchar>(rt);
        break;
    }

    case FMT_SPR_RD:
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, static_cast<uint16>(rSPR_BASE + ra));
        break;

    case FMT_SPR_WR:
        set_reg(insn->Op1, static_cast<uint16>(rSPR_BASE + ra));
        set_reg(insn->Op2, rt);
        break;

    case FMT_CH_RD:
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, static_cast<uint16>(rCH_BASE + ra));
        break;

    case FMT_CH_WR:
        set_reg(insn->Op1, static_cast<uint16>(rCH_BASE + ra));
        set_reg(insn->Op2, rt);
        break;

    case FMT_NOOPS:
        // lnop, dsync: all remaining bits are reserved (0 in valid code)
        break;

    case FMT_NOP:
        // nop: RT is false target (p. 241). Print RT only if non-zero (matches GNU spu-objdump).
        if (rt != 0)
            set_reg(insn->Op1, rt);
        insn->segpref = static_cast<uchar>(rt);
        break;

    case FMT_SYNC:
        // sync / syncc: bit 11 is C (channel sync) feature bit (p. 242)
        if (rb & 0x40)
            insn->auxpref |= SPU_AUX_C;
        break;

    case FMT_STOP:
    {
        // stop type14 (p. 238): bits 11:17 are reserved zeros.
        // Rejecting non-zero bits 11:17 prevents 32-bit LS pointers >= 0x4000
        // (such as inline switch jump table entries) from misdecoding as stop!
        if (ibits(opcode, 11, 17) != 0)
            return 0;
        uint32 stop_type = ibits(opcode, 18, 31);
        set_imm(insn->Op1, stop_type, false, dt_word);
        break;
    }

    case FMT_STOPD:
        // stopd [ra, rb, rc] (p. 239: encoding 00101000000 RB RA RC)
        // Official syntax omits operands if all zero; otherwise RA, RB, RC (GNU order).
        if (ra != 0 || rb != 0 || rt != 0)
        {
            set_reg(insn->Op1, ra);
            set_reg(insn->Op2, rb);
            set_reg(insn->Op3, rt);
        }
        break;

    case FMT_RRR:
    {
        // OP[0:3] RT[4:10] RB[11:17] RA[18:24] RC[25:31] -> mnem rt, ra, rb, rc
        uint16 rrr_rt = static_cast<uint16>(ibits(opcode, 4, 10));
        uint16 rrr_rb = static_cast<uint16>(ibits(opcode, 11, 17));
        uint16 rrr_ra = static_cast<uint16>(ibits(opcode, 18, 24));
        uint16 rrr_rc = static_cast<uint16>(ibits(opcode, 25, 31));
        set_reg(insn->Op1, rrr_rt);
        set_reg(insn->Op2, rrr_ra);
        set_reg(insn->Op3, rrr_rb);
        set_reg(insn->Op4, rrr_rc);
        break;
    }

    case FMT_BR_IND_1:
    {
        // bi ra (p. 178): bits 12=D, 13=E. D=1 & E=1 is reserved (Table 12-1 p. 251).
        bool bit_d = (rb & 0x20) != 0;
        bool bit_e = (rb & 0x10) != 0;
        if (bit_d && bit_e)
            return 0;
        if (bit_d) insn->auxpref |= SPU_AUX_D;
        if (bit_e) insn->auxpref |= SPU_AUX_E;
        set_reg(insn->Op1, ra, dt_dword);
        if (ra == rLR)
            insn->auxpref |= SPU_AUX_RET;
        break;
    }

    case FMT_IRET:
    {
        // iret [ra] (p. 179): jumps to SRR0; RA is ignored. Omit RA when 0 (matches GNU binutils).
        bool bit_d = (rb & 0x20) != 0;
        bool bit_e = (rb & 0x10) != 0;
        if (bit_d && bit_e)
            return 0;
        if (bit_d) insn->auxpref |= SPU_AUX_D;
        if (bit_e) insn->auxpref |= SPU_AUX_E;
        insn->auxpref |= SPU_AUX_RET;
        if (ra != 0)
            set_reg(insn->Op1, ra, dt_dword);
        break;
    }

    case FMT_BR_IND_2:
    {
        // bisl, bisled, biz, binz, bihz, bihnz rt, ra
        bool bit_d = (rb & 0x20) != 0;
        bool bit_e = (rb & 0x10) != 0;
        if (bit_d && bit_e)
            return 0;
        if (bit_d) insn->auxpref |= SPU_AUX_D;
        if (bit_e) insn->auxpref |= SPU_AUX_E;
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra, dt_dword);
        if (ra == rLR && d.itype != SPU_bisl && d.itype != SPU_bisled)
            insn->auxpref |= SPU_AUX_RET;
        break;
    }

    case FMT_HBR:
    {
        // hbr (p. 192): 00110101100 P /// ROH[16:17] RA[18:24] ROL[25:31]
        bool prefetch = (rb & 0x40) != 0;
        uint32 roh = rb & 0x3u;
        int32 ro9 = sign_extend((roh << 7) | rt, 9);
        if (prefetch)
        {
            insn->auxpref |= SPU_AUX_P;
            if (ro9 != 0 || ra != 0)
            {
                insn->Op1.type = o_near;
                insn->Op1.dtype = dt_code;
                insn->Op1.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(ro9) << 2), false);
                if (ra != 0)
                    set_reg(insn->Op2, ra, dt_dword);
            }
        }
        else
        {
            insn->Op1.type = o_near;
            insn->Op1.dtype = dt_code;
            insn->Op1.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(ro9) << 2), false);
            set_reg(insn->Op2, ra, dt_dword);
        }
        break;
    }

    case FMT_HBRA:
    case FMT_HBRR:
    {
        // hbra/hbrr (pp. 193-194): OP[0:6] ROH[7:8] I16[9:24] ROL[25:31]
        // FIX: ROH||ROL is 9 bits (sign bit 0x100), NOT 10 bits!
        // FIX: Both branch instruction EA and target EA wrap by & LSLR!
        uint32 roh = ibits(opcode, 7, 8);
        int32 ro9 = sign_extend((roh << 7) | rt, 9);
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);

        insn->Op1.type = o_near;
        insn->Op1.dtype = dt_code;
        insn->Op1.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(ro9) << 2), false);

        insn->Op2.type = o_near;
        insn->Op2.dtype = dt_code;
        if (d.fmt == FMT_HBRR)
            insn->Op2.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(i16) << 2), false);
        else
            insn->Op2.addr = wrap_ls_addr(insn->ea, sval_t(i16) << 2, false);
        break;
    }

    case FMT_RI7_S:
    {
        int32 i7 = sign_extend(rb, 7);
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_imm(insn->Op3, static_cast<uval_t>(static_cast<sval_t>(i7)), i7 < 0);
        break;
    }

    case FMT_RI7_U:
        // dftsv rt, ra, mask7 (p. 230)
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_imm(insn->Op3, rb & 0x7Fu, false, dt_byte);
        break;

    case FMT_RI7_LS:
    {
        // cbd, chd, cwd, cdd: rt, i7s(ra) with exact element dtype
        int32 i7 = sign_extend(rb, 7);
        set_reg(insn->Op1, rt);
        insn->Op2.type = o_displ;
        insn->Op2.reg = ra;
        insn->Op2.addr = static_cast<ea_t>(static_cast<sval_t>(i7));
        insn->Op2.dtype = static_cast<op_dtype_t>(d.extra);
        if (i7 < 0)
            insn->Op2.specval |= SPU_OP_SIGNED;
        break;
    }

    case FMT_RI8_FLT:
    {
        // cflts/cfltu (bias 173), csflt/cuflt (bias 155), pp. 220-223:
        // scale = bias - I8; undefined if scale not in [0, 127].
        uint32 i8 = ibits(opcode, 10, 17);
        int32 scale = static_cast<int32>(d.extra) - static_cast<int32>(i8);
        if (scale < 0 || scale > 127)
            return 0;
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_imm(insn->Op3, static_cast<uval_t>(scale), false, dt_byte);
        break;
    }

    case FMT_RI10_S:
    {
        int32 i10 = sign_extend(ibits(opcode, 8, 17), 10);
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_imm(insn->Op3, static_cast<uval_t>(static_cast<sval_t>(i10)), i10 < 0);
        break;
    }

    case FMT_RI10_B8U:
    {
        // andbi, orbi, xorbi, ceqbi, clgtbi: rightmost 8 bits I10 & 0xFF (pp. 99-169)
        uint32 b8 = ibits(opcode, 8, 17) & 0xFFu;
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_imm(insn->Op3, b8, false, dt_byte);
        insn->Op3.specval |= SPU_OP_BYTE8;
        break;
    }

    case FMT_RI10_B8S:
    {
        // cgtbi: signed 8-bit comparison against I10[2:9] (p. 163)
        int32 b8 = sign_extend(ibits(opcode, 8, 17) & 0xFFu, 8);
        set_reg(insn->Op1, rt);
        set_reg(insn->Op2, ra);
        set_imm(insn->Op3, static_cast<uval_t>(static_cast<sval_t>(b8)), b8 < 0, dt_byte);
        insn->Op3.specval |= SPU_OP_BYTE8;
        break;
    }

    case FMT_RI10_LS:
    {
        // lqd, stqd: rt, (sext10(I10) << 4)(ra)
        int32 disp = sign_extend(ibits(opcode, 8, 17), 10) << 4;
        set_reg(insn->Op1, rt);
        insn->Op2.type = o_displ;
        insn->Op2.reg = ra;
        insn->Op2.addr = static_cast<ea_t>(static_cast<sval_t>(disp));
        insn->Op2.dtype = dt_byte16;
        if (disp < 0)
            insn->Op2.specval |= SPU_OP_SIGNED;
        break;
    }

    case FMT_RI16_U:
    {
        uint32 i16 = ibits(opcode, 9, 24);
        set_reg(insn->Op1, rt);
        set_imm(insn->Op2, i16, false, dt_word);
        break;
    }

    case FMT_RI16_S:
    {
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        set_reg(insn->Op1, rt);
        set_imm(insn->Op2, static_cast<uval_t>(static_cast<sval_t>(i16)), i16 < 0);
        break;
    }

    case FMT_RI16_BR_R:
    {
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        insn->Op1.type = o_near;
        insn->Op1.dtype = dt_code;
        insn->Op1.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(i16) << 2), false);
        break;
    }

    case FMT_RI16_BR_A:
    {
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        insn->Op1.type = o_near;
        insn->Op1.dtype = dt_code;
        insn->Op1.addr = wrap_ls_addr(insn->ea, sval_t(i16) << 2, false);
        break;
    }

    case FMT_RI16_CBR_R:
    {
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        set_reg(insn->Op1, rt);
        insn->Op2.type = o_near;
        insn->Op2.dtype = dt_code;
        insn->Op2.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(i16) << 2), false);
        break;
    }

    case FMT_RI16_CBR_A:
    {
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        set_reg(insn->Op1, rt);
        insn->Op2.type = o_near;
        insn->Op2.dtype = dt_code;
        insn->Op2.addr = wrap_ls_addr(insn->ea, sval_t(i16) << 2, false);
        break;
    }

    case FMT_RI16_LS_A:
    {
        // lqa, stqa (pp. 34, 38): RepLeftBit(I16 || 0b00, 32) & LSLR & 0xFFFFFFF0
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        set_reg(insn->Op1, rt);
        insn->Op2.type = o_mem;
        insn->Op2.dtype = dt_byte16;
        insn->Op2.addr = wrap_ls_addr(insn->ea, sval_t(i16) << 2, true);
        break;
    }

    case FMT_RI16_LS_R:
    {
        // lqr, stqr (pp. 35, 39): (RepLeftBit(I16 || 0b00, 32) + PC) & LSLR & 0xFFFFFFF0
        int32 i16 = sign_extend(ibits(opcode, 9, 24), 16);
        set_reg(insn->Op1, rt);
        insn->Op2.type = o_mem;
        insn->Op2.dtype = dt_byte16;
        insn->Op2.addr = wrap_ls_addr(insn->ea, static_cast<sval_t>(insn->ea) + (sval_t(i16) << 2), true);
        break;
    }

    case FMT_RI18:
    {
        uint32 i18 = ibits(opcode, 7, 24);
        set_reg(insn->Op1, rt);
        set_imm(insn->Op2, i18, false, dt_dword);
        break;
    }

    default:
        return 0;
    }

    // Simplified mnemonic: ori rt, ra, 0 / shlqbyi rt, ra, 0 -> lr rt, ra
    if ((insn->itype == SPU_ori || insn->itype == SPU_shlqbyi) &&
        insn->Op3.type == o_imm && insn->Op3.value == 0)
    {
        insn->itype = SPU_lr;
        insn->Op3.type = o_void;
    }

    return insn->size;
}
