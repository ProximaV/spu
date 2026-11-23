#include "spu.hpp"

// Helper: resolve a constant integer recently loaded into reg (for large-frame SP adjust & indirect calls).
static bool trace_reg_const(ea_t ea, uint16 reg, uint32 *out_val, int max_steps = 16)
{
    ea_t cur = ea;
    for (int step = 0; step < max_steps && cur >= 4; ++step)
    {
        insn_t prev;
        ea_t pea = decode_prev_insn(&prev, cur);
        if (pea == BADADDR)
            break;
        cur = pea;

        // Stop crossing unconditional control transfers or calls (which clobber volatile regs)
        if (prev.itype == SPU_br || prev.itype == SPU_bra || prev.itype == SPU_bi ||
            prev.itype == SPU_iret || prev.itype == SPU_stop || prev.itype == SPU_stopd)
            break;
        if ((prev.itype == SPU_brsl || prev.itype == SPU_brasl || prev.itype == SPU_bisl) &&
            reg < rR80)
            break;

        if (prev.Op1.type == o_reg && prev.Op1.reg == reg &&
            (prev.get_canon_feature(PH) & CF_CHG1) != 0)
        {
            if (prev.itype == SPU_ila || prev.itype == SPU_il)
            {
                *out_val = static_cast<uint32>(prev.Op2.value);
                return true;
            }
            if (prev.itype == SPU_ilhu)
            {
                *out_val = (static_cast<uint32>(prev.Op2.value) & 0xFFFFu) << 16;
                return true;
            }
            if (prev.itype == SPU_iohl)
            {
                uint32 lo = static_cast<uint32>(prev.Op2.value) & 0xFFFFu;
                uint32 hi = 0;
                if (trace_reg_const(cur, reg, &hi, max_steps - step))
                {
                    *out_val = hi | lo;
                    return true;
                }
                return false;
            }
            if (prev.itype == SPU_lr && prev.Op2.type == o_reg)
            {
                reg = prev.Op2.reg;
                continue;
            }
            // Any other modification kills the constant
            return false;
        }
    }
    return false;
}

// Pair fusing: ilhu rX, hi16 + iohl rX, lo16 -> 32-bit address/constant xref
static void fuse_ilhu_iohl(const insn_t &insn)
{
    if (insn.itype != SPU_iohl || insn.Op1.type != o_reg || insn.Op2.type != o_imm)
        return;

    uint16 reg = insn.Op1.reg;
    uint32 lo16 = static_cast<uint32>(insn.Op2.value) & 0xFFFFu;

    ea_t cur = insn.ea;
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
            if (prev.itype == SPU_ilhu && prev.Op2.type == o_imm)
            {
                uint32 hi16 = static_cast<uint32>(prev.Op2.value) & 0xFFFFu;
                ea_t target = (ea_t(hi16) << 16) | lo16;
                if (is_loaded(target) && target != 0)
                {
                    // Add offset dref on iohl so IDA cross-references the full 32-bit target.
                    // Avoid mutating prev.ea via op_offset_ex inside emu to prevent re-analysis loops.
                    insn.add_dref(target, insn.Op2.offb, dr_O);
                }
            }
            break;
        }
    }
}

// Helper: add a stack variable reference on operand n of insn.
static void add_spu_stkvar(const insn_t &insn, sval_t v, int n, uint32 flags)
{
    func_t *pfn = get_func(insn.ea);
    if (pfn != nullptr && insn.create_stkvar(insn.ops[n], v, flags))
        op_stkvar(insn.ea, n);
}

static void handle_operand(const insn_t &insn, const op_t &op, bool is_read, bool *flow)
{
    flags64_t F = get_flags(insn.ea);
    bool is_offs = is_off(F, op.n);
    bool def_arg = is_defarg(F, op.n);
    dref_t dref_flag = is_read ? dr_R : dr_W;

    switch (op.type)
    {
    case o_imm:
        set_immd(insn.ea);
        if (insn.itype == SPU_ila && is_loaded(op.value) && op.value != 0)
        {
            if (!def_arg)
            {
                op_plain_offset(insn.ea, op.n, insn.cs);
                is_offs = true;
            }
        }
        if (is_offs)
            insn.add_off_drefs(op, dr_O, 0);
        break;

    case o_displ:
        if (is_offs)
        {
            insn.add_off_drefs(op, dref_flag, OOF_ADDR);
        }
        else if (may_create_stkvars() && !def_arg && (op.reg == rSP || op.reg == rFP))
        {
            func_t *pfn = get_func(insn.ea);
            if (pfn != nullptr)
            {
                bool allow = (op.reg == rSP) || ((pfn->flags & FUNC_FRAME) != 0);
                if (allow)
                {
                    sval_t disp = static_cast<sval_t>(static_cast<int32>(op.addr));
                    add_spu_stkvar(insn, disp, op.n, STKVAR_VALID_SIZE);
                }
            }
        }
        break;

    case o_mem:
        insn.create_op_data(op.addr, op);
        insn.add_dref(op.addr, op.offb, dref_flag);
        break;

    case o_near:
    {
        // Do not create control-flow edges for branch hint instructions (hbr/hbra/hbrr)
        if (insn.itype == SPU_hbr || insn.itype == SPU_hbra || insn.itype == SPU_hbrr)
            break;

        bool is_call = (insn.get_canon_feature(PH) & CF_CALL) != 0;
        cref_t fl = is_call ? fl_CN : fl_JN;
        insn.add_cref(op.addr, op.offb, fl);
        if (is_call && *flow && !func_does_return(op.addr))
            *flow = false;
        break;
    }

    default:
        break;
    }
}

static void add_spu_stkpnt(func_t *pfn, const insn_t &insn, sval_t delta)
{
    if (pfn == nullptr || delta == 0)
        return;
    ea_t end = insn.ea + insn.size;
    if (!is_fixed_spd(end))
        add_auto_stkpnt(pfn, end, delta);
}

static void trace_sp(const insn_t &insn)
{
    func_t *pfn = get_func(insn.ea);
    if (pfn == nullptr)
        return;

    // 1. ai sp, sp, #imm (standard stack allocation / deallocation)
    if (insn.itype == SPU_ai &&
        insn.Op1.is_reg(rSP) && insn.Op2.is_reg(rSP) && insn.Op3.type == o_imm)
    {
        sval_t delta = static_cast<sval_t>(static_cast<int32>(insn.Op3.value));
        add_spu_stkpnt(pfn, insn, delta);
        return;
    }

    // 2. lqd sp, 0(sp) (back-chain SP restore in dynamic/alloca epilogues, e.g. lv0ldr:0x01608)
    if (insn.itype == SPU_lqd &&
        insn.Op1.is_reg(rSP) && insn.Op2.type == o_displ &&
        insn.Op2.reg == rSP && insn.Op2.addr == 0)
    {
        sval_t cur_spd = get_spd(pfn, insn.ea);
        if (cur_spd < 0)
            add_spu_stkpnt(pfn, insn, -cur_spd);
        return;
    }

    // 3. a sp, sp, rN (large-frame constant adjust > 512B, or dynamic alloca)
    if (insn.itype == SPU_a && insn.Op1.is_reg(rSP) &&
        (insn.Op2.is_reg(rSP) || insn.Op3.is_reg(rSP)))
    {
        uint16 other_reg = insn.Op2.is_reg(rSP) ? insn.Op3.reg : insn.Op2.reg;
        uint32 cval = 0;
        if (trace_reg_const(insn.ea, other_reg, &cval))
        {
            sval_t delta = static_cast<sval_t>(static_cast<int32>(cval));
            if (delta >= -0x40000 && delta <= 0x40000)
            {
                add_spu_stkpnt(pfn, insn, delta);
                return;
            }
        }
        // Dynamic SP modification (VLA / alloca)
        pfn->flags |= FUNC_FUZZY_SP;
        update_func(pfn);
        return;
    }

    // 4. sf sp, rN, sp (sp = sp - rN)
    if (insn.itype == SPU_sf && insn.Op1.is_reg(rSP) && insn.Op3.is_reg(rSP))
    {
        uint32 cval = 0;
        if (trace_reg_const(insn.ea, insn.Op2.reg, &cval))
        {
            sval_t delta = -static_cast<sval_t>(static_cast<int32>(cval));
            if (delta >= -0x40000 && delta <= 0x40000)
            {
                add_spu_stkpnt(pfn, insn, delta);
                return;
            }
        }
        pfn->flags |= FUNC_FUZZY_SP;
        update_func(pfn);
    }
}

void spu_t::create_func_frame(func_t *pfn)
{
    if (pfn == nullptr)
        return;

    ea_t ea = pfn->start_ea;
    sval_t frsize = 0;
    bool found_alloc = false;
    bool uses_fp = false;

    for (int i = 0; i < 32 && ea < pfn->end_ea; ++i)
    {
        insn_t insn;
        if (decode_insn(&insn, ea) <= 0)
            break;

        // Stop prologue scan on calls or control-flow exits
        if (insn.itype == SPU_brsl || insn.itype == SPU_brasl ||
            insn.itype == SPU_bisl || insn.itype == SPU_bisled ||
            insn.itype == SPU_bi   || insn.itype == SPU_iret ||
            insn.itype == SPU_br   || insn.itype == SPU_bra ||
            insn.itype == SPU_stop || insn.itype == SPU_stopd)
        {
            break;
        }

        // Standard frame allocation: ai sp, sp, -frsize
        if (!found_alloc && insn.itype == SPU_ai &&
            insn.Op1.is_reg(rSP) && insn.Op2.is_reg(rSP) && insn.Op3.type == o_imm)
        {
            sval_t delta = static_cast<sval_t>(static_cast<int32>(insn.Op3.value));
            if (delta < 0 && -delta <= 0x40000)
            {
                frsize = -delta;
                found_alloc = true;
            }
        }
        // Large frame allocation: a sp, sp, rN (where rN was loaded with negative size)
        else if (!found_alloc && insn.itype == SPU_a && insn.Op1.is_reg(rSP) &&
                 (insn.Op2.is_reg(rSP) || insn.Op3.is_reg(rSP)))
        {
            uint16 other = insn.Op2.is_reg(rSP) ? insn.Op3.reg : insn.Op2.reg;
            uint32 cval = 0;
            if (trace_reg_const(insn.ea, other, &cval))
            {
                sval_t delta = static_cast<sval_t>(static_cast<int32>(cval));
                if (delta < 0 && -delta <= 0x40000)
                {
                    frsize = -delta;
                    found_alloc = true;
                }
            }
        }
        // Optional SPU ABI frame pointer setup: lr r127, sp or ai r127, sp, off
        else if ((insn.itype == SPU_lr || insn.itype == SPU_ai) &&
                 insn.Op1.is_reg(rFP) && insn.Op2.is_reg(rSP))
        {
            uses_fp = true;
        }

        ea += insn.size;
    }

    if (uses_fp)
        pfn->flags |= FUNC_FRAME;

    if (frsize > 0)
        add_frame(pfn, frsize, 0, 0);
}

void spu_t::is_sp_based(int *mode, const insn_t &insn, const op_t &op) const
{
    qnotused(insn);
    if (op.type == o_displ && op.reg == rFP)
        *mode = OP_FP_BASED | OP_SP_ADD;
    else
        *mode = OP_SP_BASED | OP_SP_ADD;
}

int spu_t::may_be_func(const insn_t &insn, int state) const
{
    qnotused(state);
    // stqd lr, 0x10(sp) -> canonical SPU non-leaf prologue
    if (insn.itype == SPU_stqd && insn.Op1.is_reg(rLR) &&
        insn.Op2.type == o_displ && insn.Op2.reg == rSP && insn.Op2.addr == 0x10)
        return 100;
    // stqd sp, -N(sp) -> back-chain store
    if (insn.itype == SPU_stqd && insn.Op1.is_reg(rSP) &&
        insn.Op2.type == o_displ && insn.Op2.reg == rSP &&
        static_cast<int32>(insn.Op2.addr) < 0)
        return 90;
    // ai sp, sp, -N -> stack allocation
    if (insn.itype == SPU_ai && insn.Op1.is_reg(rSP) && insn.Op2.is_reg(rSP) &&
        insn.Op3.type == o_imm && static_cast<int32>(insn.Op3.value) < 0)
        return 80;
    return 0;
}

// ===========================================================================
// SPU Switch / Jump Table Recognition (Pattern 1: Absolute, Pattern 2: Relative)
//
// Standard GCC / SN Systems SPU compiler idiom (observed in metldr:0x770,
// lv0ldr:0x19398, lv0ldr:0x1E090):
//   [ai    rIdx, rOrig, -lowcase]    ; optional lower-bound bias
//   ila    rTbl, jpt_table           ; or ilhu+iohl
//   shli   rOff, rIdx, 2             ; 4-byte entry offset
//   clgti  rCond, rIdx, ncases-1     ; unsigned bounds check
//   a      rAddr, rOff, rTbl         ; element byte address
//   lqx    rVal, rTbl, rOff          ; quadword load
//   rotqby rDst, rVal, rAddr         ; rotate target word to preferred slot 0
//   [a     rDst, rDst, rTbl]         ; optional relative-offset adjustment
//   brnz   rCond, def_label          ; out-of-range -> default
//   bi     rDst
// ===========================================================================
bool spu_t::spu_is_switch(switch_info_t *si, const insn_t &insn)
{
    if (insn.itype != SPU_bi || insn.Op1.type != o_reg || insn.Op1.reg == rLR)
        return false;

    uint16 dst_reg = insn.Op1.reg;

    // Collect up to 32 preceding instructions within the same linear run
    qvector<insn_t> prevs;
    ea_t cur = insn.ea;
    for (int step = 0; step < 32 && cur >= 4; ++step)
    {
        insn_t p;
        ea_t pea = decode_prev_insn(&p, cur);
        if (pea == BADADDR)
            break;
        cur = pea;
        // Stop at unconditional jumps/returns/calls that would break the block
        if (p.itype == SPU_br || p.itype == SPU_bra || p.itype == SPU_bi ||
            p.itype == SPU_iret || p.itype == SPU_stop || p.itype == SPU_stopd ||
            p.itype == SPU_brsl || p.itype == SPU_brasl || p.itype == SPU_bisl)
            break;
        prevs.push_back(p);
    }

    if (prevs.size() < 4)
        return false;

    // Step 1: Check optional relative add (a dst_reg, tmp_reg, rel_base_reg)
    bool is_relative = false;
    uint16 rel_base_reg = 0xFFFF;
    uint16 rot_dst_reg = dst_reg;
    size_t rot_idx = size_t(-1);

    for (size_t i = 0; i < prevs.size(); ++i)
    {
        const insn_t &p = prevs[i];
        if (p.Op1.type == o_reg && p.Op1.reg == rot_dst_reg &&
            (p.get_canon_feature(PH) & CF_CHG1) != 0)
        {
            if (p.itype == SPU_rotqby)
            {
                rot_idx = i;
                break;
            }
            if (!is_relative && p.itype == SPU_a && p.Op2.type == o_reg && p.Op3.type == o_reg)
            {
                // Could be relative jump table: a dst, offset_word, tbl_base
                // Try finding rotqby into either Op2 or Op3
                for (size_t j = i + 1; j < prevs.size(); ++j)
                {
                    if (prevs[j].itype == SPU_rotqby && prevs[j].Op1.type == o_reg)
                    {
                        if (prevs[j].Op1.reg == p.Op2.reg)
                        {
                            is_relative = true;
                            rot_dst_reg = p.Op2.reg;
                            rel_base_reg = p.Op3.reg;
                            rot_idx = j;
                            break;
                        }
                        if (prevs[j].Op1.reg == p.Op3.reg)
                        {
                            is_relative = true;
                            rot_dst_reg = p.Op3.reg;
                            rel_base_reg = p.Op2.reg;
                            rot_idx = j;
                            break;
                        }
                    }
                }
                break;
            }
            // Overwritten by something else
            return false;
        }
    }

    if (rot_idx == size_t(-1))
        return false;

    uint16 qw_reg = prevs[rot_idx].Op2.reg;

    // Step 2: Find lqx qw_reg, rA, rB before rotqby
    size_t lqx_idx = size_t(-1);
    for (size_t i = rot_idx + 1; i < prevs.size(); ++i)
    {
        const insn_t &p = prevs[i];
        if (p.Op1.type == o_reg && p.Op1.reg == qw_reg &&
            (p.get_canon_feature(PH) & CF_CHG1) != 0)
        {
            if (p.itype == SPU_lqx)
            {
                lqx_idx = i;
                break;
            }
            return false;
        }
    }
    if (lqx_idx == size_t(-1))
        return false;

    uint16 lqx_ra = prevs[lqx_idx].Op2.reg;
    uint16 lqx_rb = prevs[lqx_idx].Op3.reg;

    // Step 3: Identify which of (lqx_ra, lqx_rb) is table_base and which is byte_offset (shli idx, 2)
    ea_t table_ea = BADADDR;
    uint16 tbl_reg = 0xFFFF;
    uint16 off_reg = 0xFFFF;
    uint16 idx_reg = 0xFFFF;
    size_t shli_idx = size_t(-1);
    ea_t start_ea = prevs[lqx_idx].ea;

    // Try matching shli on either lqx_rb or lqx_ra
    for (int attempt = 0; attempt < 2 && shli_idx == size_t(-1); ++attempt)
    {
        uint16 cand_off = (attempt == 0) ? lqx_rb : lqx_ra;
        uint16 cand_tbl = (attempt == 0) ? lqx_ra : lqx_rb;
        for (size_t i = lqx_idx + 1; i < prevs.size(); ++i)
        {
            const insn_t &p = prevs[i];
            if (p.Op1.type == o_reg && p.Op1.reg == cand_off &&
                (p.get_canon_feature(PH) & CF_CHG1) != 0)
            {
                if (p.itype == SPU_shli && p.Op2.type == o_reg && p.Op3.type == o_imm && p.Op3.value == 2)
                {
                    off_reg = cand_off;
                    tbl_reg = cand_tbl;
                    idx_reg = p.Op2.reg;
                    shli_idx = i;
                    if (p.ea < start_ea) start_ea = p.ea;
                }
                break;
            }
        }
    }

    if (shli_idx == size_t(-1))
        return false;

    // Resolve table_ea from tbl_reg (ila or ilhu+iohl)
    uint32 tbl_val = 0;
    if (!trace_reg_const(prevs[lqx_idx].ea, tbl_reg, &tbl_val, 24))
        return false;
    table_ea = wrap_ls_addr(insn.ea, static_cast<sval_t>(tbl_val), false);
    if (!is_loaded(table_ea))
        return false;

    ea_t rel_elbase = table_ea;
    if (is_relative && rel_base_reg != tbl_reg)
    {
        uint32 rbv = 0;
        if (trace_reg_const(insn.ea, rel_base_reg, &rbv, 24))
            rel_elbase = wrap_ls_addr(insn.ea, static_cast<sval_t>(rbv), false);
    }

    // Step 4: Find bounds check (clgti cond_reg, idx_reg, max_case) & default branch (brnz cond_reg, def_ea)
    ea_t def_ea = BADADDR;
    uint16 cond_reg = 0xFFFF;
    size_t br_idx = size_t(-1);
    bool invert_branch = false;
    for (size_t i = 0; i < prevs.size(); ++i)
    {
        const insn_t &p = prevs[i];
        if ((p.itype == SPU_brnz || p.itype == SPU_brz) && p.Op1.type == o_reg && p.Op2.type == o_near)
        {
            cond_reg = p.Op1.reg;
            def_ea = p.Op2.addr;
            br_idx = i;
            invert_branch = (p.itype == SPU_brz);
            break;
        }
    }

    uint32 ncases = 0;
    if (cond_reg != 0xFFFF)
    {
        for (size_t i = br_idx + 1; i < prevs.size(); ++i)
        {
            const insn_t &p = prevs[i];
            if (p.Op1.type == o_reg && p.Op1.reg == cond_reg &&
                (p.get_canon_feature(PH) & CF_CHG1) != 0)
            {
                if (!invert_branch && p.itype == SPU_clgti && p.Op2.is_reg(idx_reg) && p.Op3.type == o_imm)
                {
                    int32 bound = static_cast<int32>(p.Op3.value);
                    if (bound >= 1 && bound < 4096)
                    {
                        ncases = static_cast<uint32>(bound + 1);
                        if (p.ea < start_ea) start_ea = p.ea;
                    }
                }
                else if (invert_branch && p.itype == SPU_clgti && p.Op2.is_reg(idx_reg) && p.Op3.type == o_imm)
                {
                    // Rare negated form
                    int32 bound = static_cast<int32>(p.Op3.value);
                    if (bound >= 1 && bound < 4096)
                        ncases = static_cast<uint32>(bound + 1);
                }
                else if (!invert_branch && p.itype == SPU_clgt && p.Op2.is_reg(idx_reg) && p.Op3.type == o_reg)
                {
                    uint32 bound = 0;
                    if (trace_reg_const(p.ea, p.Op3.reg, &bound) && bound >= 1 && bound < 4096)
                    {
                        ncases = bound + 1;
                        if (p.ea < start_ea) start_ea = p.ea;
                    }
                }
                break;
            }
        }
    }

    if (ncases < 2 || ncases > 4096)
        return false;

    // Step 5: Optional lower-bound bias: ai idx_reg, orig_reg, -lowcase
    sval_t lowcase = 0;
    for (size_t i = shli_idx + 1; i < prevs.size(); ++i)
    {
        const insn_t &p = prevs[i];
        if (p.Op1.type == o_reg && p.Op1.reg == idx_reg &&
            (p.get_canon_feature(PH) & CF_CHG1) != 0)
        {
            if (p.itype == SPU_ai && p.Op3.type == o_imm)
            {
                sval_t bias = static_cast<sval_t>(static_cast<int32>(p.Op3.value));
                if (bias < 0)
                {
                    lowcase = -bias;
                    if (p.ea < start_ea) start_ea = p.ea;
                }
            }
            break;
        }
    }

    // Step 6: Validate all ncases entries in the table point to valid word-aligned loaded addresses
    for (uint32 k = 0; k < ncases; ++k)
    {
        ea_t entry_ea = table_ea + k * 4;
        if (!is_loaded(entry_ea))
            return false;
        uint32 raw = get_dword(entry_ea);
        ea_t target = is_relative
            ? wrap_ls_addr(insn.ea, static_cast<sval_t>(rel_elbase) + static_cast<int32>(raw), false)
            : static_cast<ea_t>(raw);
        if ((target & 3) != 0 || !is_loaded(target))
            return false;
    }

    // Populate switch_info_t
    si->clear();
    si->flags = SWI_J32 | SWI_ELBASE;
    if (is_relative)
    {
        si->flags |= SWI_SIGNED;
        si->set_elbase(rel_elbase);
    }
    else
    {
        si->set_elbase(0);
    }
    si->set_jtable_element_size(4);
    si->set_jtable_size(static_cast<int>(ncases));
    si->startea = start_ea;
    si->jumps = table_ea;
    si->defjump = def_ea;
    si->lowcase = lowcase;
    si->set_shift(0);
    si->regnum = idx_reg;
    si->regdtype = dt_dword;

    return true;
}

int spu_t::spu_emu(const insn_t &insn)
{
    uint32 feature = insn.get_canon_feature(PH);
    bool flow = (feature & CF_STOP) == 0;

    if (feature & CF_USE1) handle_operand(insn, insn.Op1, true,  &flow);
    if (feature & CF_CHG1) handle_operand(insn, insn.Op1, false, &flow);
    if (feature & CF_USE2) handle_operand(insn, insn.Op2, true,  &flow);
    if (feature & CF_CHG2) handle_operand(insn, insn.Op2, false, &flow);
    if (feature & CF_USE3) handle_operand(insn, insn.Op3, true,  &flow);
    if (feature & CF_CHG3) handle_operand(insn, insn.Op3, false, &flow);
    if (feature & CF_USE4) handle_operand(insn, insn.Op4, true,  &flow);
    if (feature & CF_CHG4) handle_operand(insn, insn.Op4, false, &flow);

    // Handle indirect branches (bi rN where rN != lr):
    //   1. Try SPU switch/jump table recovery.
    //   2. Try constant-register target resolution (e.g., ila r14, _start; bi r14).
    if (insn.itype == SPU_bi && insn.Op1.type == o_reg && insn.Op1.reg != rLR)
    {
        switch_info_t si;
        if (get_switch_info(&si, insn.ea) > 0)
        {
            // Already recorded
        }
        else if (spu_is_switch(&si, insn))
        {
            // Clear any misdisassembled stop instructions inside the inline jump table
            del_items(si.jumps, DELIT_SIMPLE, static_cast<asize_t>(si.ncases) * 4);
            set_switch_info(insn.ea, si);
            create_switch_table(insn.ea, si);
            create_switch_xrefs(insn.ea, si);
        }
        else
        {
            uint32 target_val = 0;
            if (trace_reg_const(insn.ea, insn.Op1.reg, &target_val, 8))
            {
                ea_t target = wrap_ls_addr(insn.ea, static_cast<sval_t>(target_val), false);
                if (is_loaded(target) && target != 0)
                    insn.add_cref(target, 0, fl_JN);
            }
            else
            {
                remember_problem(PR_JUMP, insn.ea);
            }
        }
    }

    // Handle indirect calls (bisl rt, ra): resolve constant-register targets if statically known
    if ((insn.itype == SPU_bisl || insn.itype == SPU_bisled) && insn.Op2.type == o_reg)
    {
        uint32 target_val = 0;
        if (trace_reg_const(insn.ea, insn.Op2.reg, &target_val, 8))
        {
            ea_t target = wrap_ls_addr(insn.ea, static_cast<sval_t>(target_val), false);
            if (is_loaded(target) && target != 0)
            {
                insn.add_cref(target, 0, fl_CN);
                if (insn.itype == SPU_bisl && !func_does_return(target))
                    flow = false;
            }
        }
    }

    // Create fall-through flow edge if execution continues
    if (flow)
        add_cref(insn.ea, insn.ea + insn.size, fl_F);

    // 32-bit immediate pair fusing: ilhu rX, hi16 + iohl rX, lo16
    fuse_ilhu_iohl(insn);

    // Create stack var references for ai rd, sp, offs (where rd != sp) and ai rd, r127, offs
    if (may_create_stkvars() && insn.itype == SPU_ai &&
        insn.Op1.type == o_reg && !insn.Op1.is_reg(rSP) && !insn.Op1.is_reg(rFP) &&
        insn.Op2.type == o_reg && (insn.Op2.is_reg(rSP) || insn.Op2.is_reg(rFP)) &&
        insn.Op3.type == o_imm && !is_defarg(get_flags(insn.ea), 2))
    {
        func_t *pfn = get_func(insn.ea);
        if (pfn != nullptr && (insn.Op2.is_reg(rSP) || (pfn->flags & FUNC_FRAME) != 0))
        {
            sval_t offs = static_cast<sval_t>(static_cast<int32>(insn.Op3.value));
            add_spu_stkvar(insn, offs, 2, 0);
        }
    }

    // Stack pointer delta tracing
    if (may_trace_sp())
    {
        if (flow)
            trace_sp(insn);
        else
            recalc_spd(insn.ea);
    }

    return 1;
}
