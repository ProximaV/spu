#include "spu.hpp"

const char *spu_channel_sym_name(uint32 ch)
{
    switch (ch)
    {
    // CBEA 1.01 architectural SPU channels (0..30)
    case 0:  return "SPU_RdEventStat";
    case 1:  return "SPU_WrEventMask";
    case 2:  return "SPU_WrEventAck";
    case 3:  return "SPU_RdSigNotify1";
    case 4:  return "SPU_RdSigNotify2";
    case 7:  return "SPU_WrDec";
    case 8:  return "SPU_RdDec";
    case 9:  return "MFC_WrMSSyncReq";
    case 11: return "SPU_RdEventMask";
    case 12: return "MFC_RdTagMask";
    case 13: return "SPU_RdMachStat";
    case 14: return "SPU_WrSRR0";
    case 15: return "SPU_RdSRR0";
    case 16: return "MFC_LSA";
    case 17: return "MFC_EAH";
    case 18: return "MFC_EAL";
    case 19: return "MFC_Size";
    case 20: return "MFC_TagID";
    case 21: return "MFC_Cmd";
    case 22: return "MFC_WrTagMask";
    case 23: return "MFC_WrTagUpdate";
    case 24: return "MFC_RdTagStat";
    case 25: return "MFC_RdListStallStat";
    case 26: return "MFC_WrListStallAck";
    case 27: return "MFC_RdAtomicStat";
    case 28: return "SPU_WrOutMbox";
    case 29: return "SPU_RdInMbox";
    case 30: return "SPU_WrOutIntrMbox";
    // PS3 SPU Isolation hardware channels (64..68)
    case 64: return "SPU_IsoCntl";
    case 65: return "SPU_IsoStat";
    case 66: return "SPU_IsoRootKey";
    case 67: return "SPU_IsoKey";
    case 68: return "SPU_IsoIdent";
    default: return nullptr;
    }
}

const char *spu_mfc_cmd_name(uint32 cmd)
{
    switch (cmd & 0xFFu)
    {
    // CBEA v1.01 Table 6-2: MFC Command Opcodes
    case 0x20: return "PUT";
    case 0x21: return "PUTB";
    case 0x22: return "PUTF";
    case 0x24: return "PUTL";
    case 0x25: return "PUTLB";
    case 0x26: return "PUTLF";
    case 0x28: return "PUTS";
    case 0x29: return "PUTBS";
    case 0x2A: return "PUTFS";
    case 0x30: return "PUTR";
    case 0x31: return "PUTRB";
    case 0x32: return "PUTRF";
    case 0x34: return "PUTRL";
    case 0x35: return "PUTRLB";
    case 0x36: return "PUTRLF";
    case 0x40: return "GET";
    case 0x41: return "GETB";
    case 0x42: return "GETF";
    case 0x44: return "GETL";
    case 0x45: return "GETLB";
    case 0x46: return "GETLF";
    case 0x48: return "GETS";
    case 0x49: return "GETBS";
    case 0x4A: return "GETFS";
    case 0xA0: return "SNDSIG";
    case 0xA1: return "SNDSIGB";
    case 0xA2: return "SNDSIGF";
    case 0xB0: return "PUTLLUC";
    case 0xB4: return "PUTLLC";
    case 0xB8: return "PUTQLLUC";
    case 0xC0: return "BARRIER";
    case 0xC8: return "MFCEIEIO";
    case 0xCC: return "MFCSYNC";
    case 0xD0: return "GETLLAR";
    default:   return nullptr;
    }
}

void format_dftsv_mask(qstring *out, uint32 mask7)
{
    static const char *const kClasses[7] = {
        "NaN", "+Inf", "-Inf", "+0", "-0", "+Denorm", "-Denorm"
    };
    out->clear();
    for (int i = 0; i < 7; ++i)
    {
        if (mask7 & (0x40u >> i))
        {
            if (!out->empty())
                out->append('|');
            out->append(kClasses[i]);
        }
    }
    if (out->empty())
        *out = "none";
}

void spu_t::format_reg_name(qstring *out, uint16 reg) const
{
    bool gnu = (opt_flags & SPU_OPT_GNU_REGS) != 0;
    bool sym_ch = (opt_flags & SPU_OPT_SYM_CHANNELS) != 0;

    if (reg < 128)
    {
        if (gnu)
            out->sprnt("$%u", reg);
        else if (reg == rLR)
            *out = "lr";
        else if (reg == rSP)
            *out = "sp";
        else
            out->sprnt("r%u", reg);
    }
    else if (reg >= rSPR_BASE && reg < rSPR_BASE + 128)
    {
        uint32 sp = reg - rSPR_BASE;
        out->sprnt(gnu ? "$sp%u" : "sp%u", sp);
    }
    else if (reg >= rCH_BASE && reg < rCH_BASE + 128)
    {
        uint32 ch = reg - rCH_BASE;
        if (sym_ch)
        {
            if (const char *sym = spu_channel_sym_name(ch))
            {
                *out = sym;
                return;
            }
        }
        out->sprnt(gnu ? "$ch%u" : "ch%u", ch);
    }
    else if (reg == rCS)
    {
        *out = "CS";
    }
    else if (reg == rDS)
    {
        *out = "DS";
    }
    else
    {
        out->sprnt("?reg%u", reg);
    }
}

// Look backwards a few instructions in the same basic block to resolve an immediate loaded into reg.
static bool resolve_recent_imm(ea_t ea, uint16 reg, uint32 *out_val, bool *from_ilhu = nullptr)
{
    ea_t cur = ea;
    for (int step = 0; step < 12 && cur >= 4; ++step)
    {
        insn_t prev;
        ea_t pea = decode_prev_insn(&prev, cur);
        if (pea == BADADDR)
            break;
        cur = pea;
        if (prev.itype == SPU_br || prev.itype == SPU_bra || prev.itype == SPU_bi ||
            prev.itype == SPU_brsl || prev.itype == SPU_brasl || prev.itype == SPU_bisl)
            break;
        if (prev.Op1.type == o_reg && prev.Op1.reg == reg &&
            (prev.get_canon_feature(PH) & CF_CHG1) != 0)
        {
            if (prev.itype == SPU_il || prev.itype == SPU_ila || prev.itype == SPU_ilh)
            {
                *out_val = static_cast<uint32>(prev.Op2.value);
                if (from_ilhu) *from_ilhu = false;
                return true;
            }
            if (prev.itype == SPU_iohl)
            {
                uint32 lo = static_cast<uint32>(prev.Op2.value) & 0xFFFFu;
                uint32 hi = 0;
                if (resolve_recent_imm(cur, reg, &hi, from_ilhu))
                {
                    *out_val = hi | lo;
                    return true;
                }
                return false;
            }
            if (prev.itype == SPU_ilhu)
            {
                *out_val = (static_cast<uint32>(prev.Op2.value) & 0xFFFFu) << 16;
                if (from_ilhu) *from_ilhu = true;
                return true;
            }
            // Any other write to reg clobbers it
            return false;
        }
    }
    return false;
}

bool spu_t::get_autocmt(qstring *buf, const insn_t &insn) const
{
    const char *base = spu_insn_comment(insn.itype);
    if (base == nullptr)
        return false;

    // Channel instructions: always include the original numeric channel ID [chN]
    // plus MFC DMA command decoding when writing MFC_Cmd (ch21).
    if (insn.itype == SPU_rdch || insn.itype == SPU_rchcnt || insn.itype == SPU_wrch)
    {
        const op_t &chop = (insn.itype == SPU_wrch) ? insn.Op1 : insn.Op2;
        if (chop.type == o_reg && chop.reg >= rCH_BASE && chop.reg < rCH_BASE + 128)
        {
            uint32 ch = chop.reg - rCH_BASE;
            const char *sym = spu_channel_sym_name(ch);
            if ((opt_flags & SPU_OPT_SYM_CHANNELS) != 0 && sym != nullptr)
                buf->sprnt("%s [ch%u]", base, ch);
            else if (sym != nullptr)
                buf->sprnt("%s [%s / ch%u]", base, sym, ch);
            else
                buf->sprnt("%s [ch%u]", base, ch);

            // Decode MFC DMA command code when writing to ch21 (MFC_Cmd)
            if (insn.itype == SPU_wrch && ch == 21 && insn.Op2.type == o_reg)
            {
                uint32 cmd_val = 0;
                if (resolve_recent_imm(insn.ea, insn.Op2.reg, &cmd_val))
                {
                    if (const char *mfc = spu_mfc_cmd_name(cmd_val))
                        buf->cat_sprnt(" (MFC %s, 0x%02X)", mfc, cmd_val & 0xFFu);
                }
            }
            return true;
        }
    }

    // dftsv: decode the 7-bit IEEE special-value test mask
    if (insn.itype == SPU_dftsv && insn.Op3.type == o_imm)
    {
        qstring mask_str;
        format_dftsv_mask(&mask_str, static_cast<uint32>(insn.Op3.value));
        buf->sprnt("%s [%s]", base, mask_str.c_str());
        return true;
    }

    // iohl paired with ilhu: show reconstructed 32-bit immediate value
    if (insn.itype == SPU_iohl && insn.Op1.type == o_reg && insn.Op2.type == o_imm)
    {
        uint32 hi = 0;
        bool from_ilhu = false;
        if (resolve_recent_imm(insn.ea, insn.Op1.reg, &hi, &from_ilhu) && from_ilhu)
        {
            uint32 full32 = hi | (static_cast<uint32>(insn.Op2.value) & 0xFFFFu);
            buf->sprnt("%s (= 0x%08X)", base, full32);
            return true;
        }
    }

    // Return / conditional return annotation
    if ((insn.auxpref & SPU_AUX_RET) != 0)
    {
        if (insn.itype == SPU_bi)
        {
            *buf = "Return (Branch Indirect to LR)";
            return true;
        }
        if (insn.itype == SPU_biz || insn.itype == SPU_binz ||
            insn.itype == SPU_bihz || insn.itype == SPU_bihnz)
        {
            buf->sprnt("%s (Conditional Return)", base);
            return true;
        }
    }

    // Optional false-target visibility for halt / fscrwr instructions
    if ((opt_flags & SPU_OPT_SHOW_FALSE_T) != 0 && insn.segpref != 0 &&
        (insn.itype == SPU_heq || insn.itype == SPU_heqi ||
         insn.itype == SPU_hgt || insn.itype == SPU_hgti ||
         insn.itype == SPU_hlgt || insn.itype == SPU_hlgti ||
         insn.itype == SPU_fscrwr))
    {
        buf->sprnt("%s (false target r%u)", base, static_cast<unsigned>(insn.segpref));
        return true;
    }

    *buf = base;
    return true;
}

class out_spu_t : public outctx_t
{
    out_spu_t() = delete;
public:
    spu_t &pm() { return *static_cast<spu_t *>(procmod); }
    void out_mnem_spu();
    bool out_operand(const op_t &x);
    void out_insn();
};
CASSERT(sizeof(out_spu_t) == sizeof(outctx_t));

DECLARE_OUT_FUNCS_WITHOUT_OUTMNEM(out_spu_t)

void out_spu_t::out_mnem_spu()
{
    qstring postfix;
    if (insn.auxpref & SPU_AUX_D) postfix.append('d');
    if (insn.auxpref & SPU_AUX_E) postfix.append('e');
    if (insn.auxpref & SPU_AUX_P) postfix.append('p');
    if (insn.auxpref & SPU_AUX_C) postfix.append('c');
    out_mnem(15, postfix.empty() ? nullptr : postfix.c_str());
}

bool out_spu_t::out_operand(const op_t &x)
{
    uint32 signed_flag = (x.specval & SPU_OP_SIGNED) ? OOF_SIGNED : 0;

    switch (x.type)
    {
    case o_void:
        return false;

    case o_reg:
    {
        qstring rname;
        pm().format_reg_name(&rname, x.reg);
        out_register(rname.c_str());
        return true;
    }

    case o_imm:
    {
        uint32 width = (x.specval & SPU_OP_BYTE8) ? OOFW_8 : OOFW_32;
        out_value(x, OOFW_IMM | signed_flag | width);
        return true;
    }

    case o_near:
    case o_mem:
    {
        if (!out_name_expr(x, x.addr, BADADDR))
        {
            out_tagon(COLOR_ERROR);
            out_btoa(x.addr, 16);
            out_tagoff(COLOR_ERROR);
            remember_problem(PR_NONAME, insn.ea);
        }
        return true;
    }

    case o_displ:
    {
        out_value(x, OOF_ADDR | OOFW_32 | signed_flag);
        out_symbol('(');
        qstring rname;
        pm().format_reg_name(&rname, x.reg);
        out_register(rname.c_str());
        out_symbol(')');
        return true;
    }

    default:
        return false;
    }
}

void out_spu_t::out_insn()
{
    out_mnem_spu();

    if (insn.Op1.type != o_void)
    {
        out_one_operand(0);
        for (int i = 1; i < 4; ++i)
        {
            if (insn.ops[i].type == o_void)
                break;
            out_symbol(',');
            out_char(' ');
            out_one_operand(i);
        }
    }

    out_immchar_cmts();
    set_gen_cmt();
    flush_outbuf();
}

void spu_out_mnem(outctx_t &ctx)
{
    static_cast<out_spu_t &>(ctx).out_mnem_spu();
}
