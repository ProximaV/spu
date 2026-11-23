// Cell Broadband Engine SPU processor module for IDA Pro 9.5
// Based on Synergistic Processor Unit Instruction Set Architecture v1.2 (27 Jan 2007)
// and SPU Application Binary Interface Specification v1.9.

#include "spu.hpp"
#include <algorithm>

extern void spu_out_mnem(outctx_t &ctx);

int data_id;

// ---------------------------------------------------------------------------
// Register name table (indices 0..385 match spu.py & spudec layout exactly)
// ---------------------------------------------------------------------------
static const char *const reg_names[] = {
    // 0..127: GPRs (r0=lr, r1=sp, r2..r127)
    "lr",   "sp",   "r2",   "r3",   "r4",   "r5",   "r6",   "r7",
    "r8",   "r9",   "r10",  "r11",  "r12",  "r13",  "r14",  "r15",
    "r16",  "r17",  "r18",  "r19",  "r20",  "r21",  "r22",  "r23",
    "r24",  "r25",  "r26",  "r27",  "r28",  "r29",  "r30",  "r31",
    "r32",  "r33",  "r34",  "r35",  "r36",  "r37",  "r38",  "r39",
    "r40",  "r41",  "r42",  "r43",  "r44",  "r45",  "r46",  "r47",
    "r48",  "r49",  "r50",  "r51",  "r52",  "r53",  "r54",  "r55",
    "r56",  "r57",  "r58",  "r59",  "r60",  "r61",  "r62",  "r63",
    "r64",  "r65",  "r66",  "r67",  "r68",  "r69",  "r70",  "r71",
    "r72",  "r73",  "r74",  "r75",  "r76",  "r77",  "r78",  "r79",
    "r80",  "r81",  "r82",  "r83",  "r84",  "r85",  "r86",  "r87",
    "r88",  "r89",  "r90",  "r91",  "r92",  "r93",  "r94",  "r95",
    "r96",  "r97",  "r98",  "r99",  "r100", "r101", "r102", "r103",
    "r104", "r105", "r106", "r107", "r108", "r109", "r110", "r111",
    "r112", "r113", "r114", "r115", "r116", "r117", "r118", "r119",
    "r120", "r121", "r122", "r123", "r124", "r125", "r126", "r127",

    // 128..255: Special-Purpose Registers (sp0..sp127)
    "sp0",   "sp1",   "sp2",   "sp3",   "sp4",   "sp5",   "sp6",   "sp7",
    "sp8",   "sp9",   "sp10",  "sp11",  "sp12",  "sp13",  "sp14",  "sp15",
    "sp16",  "sp17",  "sp18",  "sp19",  "sp20",  "sp21",  "sp22",  "sp23",
    "sp24",  "sp25",  "sp26",  "sp27",  "sp28",  "sp29",  "sp30",  "sp31",
    "sp32",  "sp33",  "sp34",  "sp35",  "sp36",  "sp37",  "sp38",  "sp39",
    "sp40",  "sp41",  "sp42",  "sp43",  "sp44",  "sp45",  "sp46",  "sp47",
    "sp48",  "sp49",  "sp50",  "sp51",  "sp52",  "sp53",  "sp54",  "sp55",
    "sp56",  "sp57",  "sp58",  "sp59",  "sp60",  "sp61",  "sp62",  "sp63",
    "sp64",  "sp65",  "sp66",  "sp67",  "sp68",  "sp69",  "sp70",  "sp71",
    "sp72",  "sp73",  "sp74",  "sp75",  "sp76",  "sp77",  "sp78",  "sp79",
    "sp80",  "sp81",  "sp82",  "sp83",  "sp84",  "sp85",  "sp86",  "sp87",
    "sp88",  "sp89",  "sp90",  "sp91",  "sp92",  "sp93",  "sp94",  "sp95",
    "sp96",  "sp97",  "sp98",  "sp99",  "sp100", "sp101", "sp102", "sp103",
    "sp104", "sp105", "sp106", "sp107", "sp108", "sp109", "sp110", "sp111",
    "sp112", "sp113", "sp114", "sp115", "sp116", "sp117", "sp118", "sp119",
    "sp120", "sp121", "sp122", "sp123", "sp124", "sp125", "sp126", "sp127",

    // 256..383: Channels (CBEA 0..30 + PS3 Isolation 64..68 symbolic, others chN)
    "SPU_RdEventStat", "SPU_WrEventMask", "SPU_WrEventAck", "SPU_RdSigNotify1",
    "SPU_RdSigNotify2", "ch5", "ch6", "SPU_WrDec",
    "SPU_RdDec", "MFC_WrMSSyncReq", "ch10", "SPU_RdEventMask",
    "MFC_RdTagMask", "SPU_RdMachStat", "SPU_WrSRR0", "SPU_RdSRR0",
    "MFC_LSA", "MFC_EAH", "MFC_EAL", "MFC_Size",
    "MFC_TagID", "MFC_Cmd", "MFC_WrTagMask", "MFC_WrTagUpdate",
    "MFC_RdTagStat", "MFC_RdListStallStat", "MFC_WrListStallAck", "MFC_RdAtomicStat",
    "SPU_WrOutMbox", "SPU_RdInMbox", "SPU_WrOutIntrMbox", "ch31",
    "ch32",  "ch33",  "ch34",  "ch35",  "ch36",  "ch37",  "ch38",  "ch39",
    "ch40",  "ch41",  "ch42",  "ch43",  "ch44",  "ch45",  "ch46",  "ch47",
    "ch48",  "ch49",  "ch50",  "ch51",  "ch52",  "ch53",  "ch54",  "ch55",
    "ch56",  "ch57",  "ch58",  "ch59",  "ch60",  "ch61",  "ch62",  "ch63",
    "SPU_IsoCntl", "SPU_IsoStat", "SPU_IsoRootKey", "SPU_IsoKey",
    "SPU_IsoIdent", "ch69",  "ch70",  "ch71",
    "ch72",  "ch73",  "ch74",  "ch75",  "ch76",  "ch77",  "ch78",  "ch79",
    "ch80",  "ch81",  "ch82",  "ch83",  "ch84",  "ch85",  "ch86",  "ch87",
    "ch88",  "ch89",  "ch90",  "ch91",  "ch92",  "ch93",  "ch94",  "ch95",
    "ch96",  "ch97",  "ch98",  "ch99",  "ch100", "ch101", "ch102", "ch103",
    "ch104", "ch105", "ch106", "ch107", "ch108", "ch109", "ch110", "ch111",
    "ch112", "ch113", "ch114", "ch115", "ch116", "ch117", "ch118", "ch119",
    "ch120", "ch121", "ch122", "ch123", "ch124", "ch125", "ch126", "ch127",

    // 384..385: Virtual segment registers
    "CS", "DS"
};

static_assert(qnumber(reg_names) == rREG_COUNT, "reg_names array must match rREG_COUNT");

// ---------------------------------------------------------------------------
// GNU Assembler definition
// ---------------------------------------------------------------------------
static const asm_t spu_gnu_asm = {
    ASH_HEXF3 | AS_COLON | ASB_BINF0 | ASO_OCTF1 | AS_NCMAS,
    0,
    "GNU assembler",
    0,
    nullptr,        // header
    ".org",         // origin
    ".end",         // end
    ";",            // cmnt
    '"',            // ascsep
    '\'',           // accsep
    "\"'",          // esccodes
    ".ascii",       // a_ascii
    ".byte",        // a_byte
    ".short",       // a_word
    ".int",         // a_dword
    ".quad",        // a_qword
    ".int128",      // a_oword
    ".float",       // a_float
    ".double",      // a_double
    nullptr,        // a_tbyte
    nullptr,        // a_packreal
    nullptr,        // a_dups
    "dfs %s",       // a_bss
    ".equ",         // a_equ
    "seg",          // a_seg
    ".",            // a_curip
    nullptr,        // out_func_header
    nullptr,        // out_func_footer
    "public",       // a_public
    "weak",         // a_weak
    ".extrn",       // a_extrn
    "",             // a_comdef
    nullptr,        // get_type_name
    ".align",       // a_align
    '(',            // lbrace
    ')',            // rbrace
    "%",            // a_mod
    "&",            // a_band
    "|",            // a_bor
    "^",            // a_xor
    "~",            // a_bnot
    "<<",           // a_shl
    ">>",           // a_shr
    "size %s",      // a_sizeof_fmt
    0,              // flag2
    nullptr,        // cmnt2
    nullptr,        // low8
    nullptr,        // high8
    nullptr,        // low16
    nullptr,        // high16
    nullptr,        // include_fmt
    nullptr,        // vstruc_fmt
    nullptr,        // rva
    nullptr,        // yword
};

static const asm_t *const assemblers[] = {
    &spu_gnu_asm,
    nullptr
};

// ---------------------------------------------------------------------------
// Alignment instruction detection: 4-byte nop (0x40200000..7F) & lnop (0x00200000)
// ---------------------------------------------------------------------------
static int spu_is_align_insn(ea_t ea)
{
    if ((ea & 3) != 0 || !is_loaded(ea))
        return 0;
    uint32 w = get_dword(ea);
    // lnop: 00000000001 0000000 0000000 0000000 = 0x00200000
    // nop:  01000000001 0000000 0000000 RT      = 0x40200000..0x4020007F
    if (w == 0x00200000u || (w & 0xFFFFFF80u) == 0x40200000u)
        return 4;
    return 0;
}

// ---------------------------------------------------------------------------
// Register metadata for IDA type system & debugger interoperability
// ---------------------------------------------------------------------------
static int spu_get_reg_info(const char **main_regname, bitrange_t *bitrange, const char *regname)
{
    if (regname == nullptr || regname[0] == '\0')
        return -1;

    if (strieq(regname, "lr") || strieq(regname, "r0") || strieq(regname, "$0"))
    {
        if (main_regname) *main_regname = "lr";
        if (bitrange) bitrange->reset();
        return 1;
    }
    if (strieq(regname, "sp") || strieq(regname, "r1") || strieq(regname, "$1"))
    {
        if (main_regname) *main_regname = "sp";
        if (bitrange) bitrange->reset();
        return 1;
    }

    // Parse r2..r127 or $2..$127
    if ((regname[0] == 'r' || regname[0] == 'R' || regname[0] == '$') && qisdigit(regname[1]))
    {
        char *endp = nullptr;
        long idx = strtol(regname + 1, &endp, 10);
        if (endp != nullptr && *endp == '\0' && idx >= 0 && idx < 128)
        {
            if (main_regname) *main_regname = reg_names[idx];
            if (bitrange) bitrange->reset();
            return 1;
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// SPU ABI v1.9 Calling Convention (r3..r74 args/returns, 16-byte stack spill)
// ---------------------------------------------------------------------------
static bool calc_spu_retloc(argloc_t *retloc, const tinfo_t &type, cm_t cc)
{
    qnotused(cc);
    if (type.is_void())
        return true;

    size_t size = type.get_size();
    if (size == BADSIZE || size == 0)
        return false;

    if (size <= 16)
    {
        retloc->set_reg1(rR3);
        return true;
    }
    if (size <= 128)
    {
        // Multi-register return in contiguous r3..rN (16 bytes per register)
        size_t nregs = (size + 15) / 16;
        if (nregs == 2)
        {
            retloc->set_reg2(rR3, rR3 + 1);
            return true;
        }
        scattered_aloc_t *sc = new scattered_aloc_t();
        for (size_t i = 0; i < nregs; ++i)
        {
            argpart_t &ap = sc->push_back();
            ap.set_reg1(static_cast<int>(rR3 + i));
            ap.off = static_cast<uint16>(i * 16);
            ap.size = static_cast<uint16>((std::min)(size_t(16), size - i * 16));
        }
        retloc->consume_scattered(sc);
        return true;
    }
    // > 128 bytes: returned via hidden pointer passed in r3
    retloc->set_reg1(rR3);
    return true;
}

static bool calc_spu_arglocs(func_type_data_t *fti)
{
    if (!calc_spu_retloc(&fti->retloc, fti->rettype, fti->get_cc()))
        return false;

    int next_reg = rR3;
    // If return value > 128 bytes, hidden return pointer occupies r3
    size_t retsize = fti->rettype.is_void() ? 0 : fti->rettype.get_size();
    if (retsize != BADSIZE && retsize > 128)
        ++next_reg;

    // Overflow stack arguments start at caller SP + 0x20 (after back-chain + LR save slots)
    sval_t spoff = 0x20;

    for (size_t i = 0; i < fti->size(); ++i)
    {
        funcarg_t &fa = (*fti)[i];
        size_t size = fa.type.get_size();
        if (size == BADSIZE || size == 0)
            size = 4;

        size_t slots = (size + 15) / 16;
        if (slots == 0) slots = 1;

        if (next_reg + static_cast<int>(slots) - 1 <= rR74)
        {
            if (slots == 1)
            {
                fa.argloc.set_reg1(next_reg);
            }
            else if (slots == 2)
            {
                fa.argloc.set_reg2(next_reg, next_reg + 1);
            }
            else
            {
                scattered_aloc_t *sc = new scattered_aloc_t();
                for (size_t k = 0; k < slots; ++k)
                {
                    argpart_t &ap = sc->push_back();
                    ap.set_reg1(next_reg + static_cast<int>(k));
                    ap.off = static_cast<uint16>(k * 16);
                    ap.size = static_cast<uint16>((std::min)(size_t(16), size - k * 16));
                }
                fa.argloc.consume_scattered(sc);
            }
            next_reg += static_cast<int>(slots);
        }
        else
        {
            spoff = (spoff + 15) & ~sval_t(15);
            fa.argloc.set_stkoff(spoff);
            spoff += static_cast<sval_t>(slots * 16);
        }
    }

    fti->stkargs = (spoff > 0x20) ? spoff : 0;
    return true;
}

static void configure_spu_compiler_and_til()
{
    inf_set_be(true);
    inf_set_cc_id(COMP_GNU);
    inf_set_cc_cm(CM_N32_F48 | CM_CC_CDECL);
    inf_set_cc_defalign(4);
    inf_set_cc_size_i(4);
    inf_set_cc_size_b(1);
    inf_set_cc_size_e(4);
    inf_set_cc_size_s(2);
    inf_set_cc_size_l(4);
    inf_set_cc_size_ll(8);
    inf_set_cc_size_ldbl(8);
    add_til("gnucmn", ADDTIL_DEFAULT);
    add_til("spu_cbea", ADDTIL_DEFAULT);
}

// ---------------------------------------------------------------------------
// Configuration persistence & IDP options dialog
// ---------------------------------------------------------------------------
void spu_t::save_to_idb()
{
    if (helper != BADNODE)
    {
        helper.altset(static_cast<nodeidx_t>(-1), opt_flags | 0x80000000u);
        helper.altset(static_cast<nodeidx_t>(-2), lslr);
    }
}

void spu_t::load_from_idb()
{
    ioh.restore_device();
    if (helper != BADNODE)
    {
        uval_t v = helper.altval(static_cast<nodeidx_t>(-1));
        if (v & 0x80000000u)
            opt_flags = static_cast<uint32>(v & 0x7FFFFFFFu);
        uval_t lv = helper.altval(static_cast<nodeidx_t>(-2));
        if (lv != 0)
            lslr = static_cast<uint32>(lv);
    }
    // Upgrade legacy IDBs created by spu.py (which left compiler=COMP_UNK, align=0)
    if (inf_get_cc_id() == COMP_UNK || inf_get_cc_defalign() == 0)
    {
        configure_spu_compiler_and_til();
    }
}

const char *spu_t::set_idp_options(const char *keyword, int value_type, const void *value, bool idb_loaded)
{
    if (keyword == nullptr)
    {
        // Interactive configuration dialog
        static const char form[] =
            "HELP\n"
            "Cell Broadband Engine SPU processor module options.\n"
            "ENDHELP\n"
            "SPU Processor Options\n"
            "<#Use symbolic CBEA/PS3 channel names (e.g. MFC_Cmd) with [chN] comment#Symbolic channel names:C>\n"
            "<#Use GNU register syntax ($0..$127, $chN, $spN)#GNU register names ($N):C>\n"
            "<#Annotate non-zero false-target RT on halt/fscrwr instructions#Show false-target RT in comments:C>>\n"
            "<#Local Store Limit Register mask (default 0x3FFFF = 256 KB)#LSLR mask:M:10:12::>\n";

        ushort cflags = 0;
        if (opt_flags & SPU_OPT_SYM_CHANNELS) cflags |= 1;
        if (opt_flags & SPU_OPT_GNU_REGS)     cflags |= 2;
        if (opt_flags & SPU_OPT_SHOW_FALSE_T) cflags |= 4;
        uval_t lslr_val = lslr;

        if (ask_form(form, &cflags, &lslr_val) > 0)
        {
            opt_flags = 0;
            if (cflags & 1) opt_flags |= SPU_OPT_SYM_CHANNELS;
            if (cflags & 2) opt_flags |= SPU_OPT_GNU_REGS;
            if (cflags & 4) opt_flags |= SPU_OPT_SHOW_FALSE_T;
            if (lslr_val >= 0xFFF)
                lslr = static_cast<uint32>(lslr_val);
            if (idb_loaded)
                save_to_idb();
        }
        return IDPOPT_OK;
    }

    if (streq(keyword, "SPU_SYM_CHANNELS"))
    {
        if (value_type != IDPOPT_BIT) return IDPOPT_BADTYPE;
        setflag(opt_flags, SPU_OPT_SYM_CHANNELS, (*static_cast<const int *>(value)) != 0);
        if (idb_loaded) save_to_idb();
        return IDPOPT_OK;
    }
    if (streq(keyword, "SPU_GNU_REGS"))
    {
        if (value_type != IDPOPT_BIT) return IDPOPT_BADTYPE;
        setflag(opt_flags, SPU_OPT_GNU_REGS, (*static_cast<const int *>(value)) != 0);
        if (idb_loaded) save_to_idb();
        return IDPOPT_OK;
    }
    if (streq(keyword, "SPU_SHOW_FALSE_T"))
    {
        if (value_type != IDPOPT_BIT) return IDPOPT_BADTYPE;
        setflag(opt_flags, SPU_OPT_SHOW_FALSE_T, (*static_cast<const int *>(value)) != 0);
        if (idb_loaded) save_to_idb();
        return IDPOPT_OK;
    }
    if (streq(keyword, "SPU_LSLR"))
    {
        if (value_type != IDPOPT_NUM) return IDPOPT_BADTYPE;
        uint32 v = static_cast<uint32>(*static_cast<const uval_t *>(value));
        if (v >= 0xFFF)
            lslr = v;
        if (idb_loaded) save_to_idb();
        return IDPOPT_OK;
    }

    return IDPOPT_BADKEY;
}

// ---------------------------------------------------------------------------
// IDB listener & procmod event dispatcher
// ---------------------------------------------------------------------------
ssize_t idaapi spu_idb_listener_t::on_event(ssize_t code, va_list)
{
    switch (code)
    {
    case idb_event::auto_empty_finally:
    {
        til_t *ti = get_idati();
        bool has_spu_til = false;
        if (ti != nullptr)
        {
            for (int i = 0; i < ti->nbases; ++i)
            {
                if (ti->base[i] != nullptr && ti->base[i]->name != nullptr &&
                    stristr(ti->base[i]->name, "spu_cbea") != nullptr)
                {
                    has_spu_til = true;
                    break;
                }
            }
        }
        if (!has_spu_til)
            add_til("spu_cbea", ADDTIL_DEFAULT);
        break;
    }
    default:
        break;
    }
    return 0;
}

static ssize_t idaapi notify(void *, int msgid, va_list)
{
    if (msgid == processor_t::ev_get_procmod)
        return size_t(SET_MODULE_DATA(spu_t));
    return 0;
}

ssize_t idaapi spu_t::on_event(ssize_t msgid, va_list va)
{
    switch (msgid)
    {
    case processor_t::ev_init:
        hook_event_listener(HT_IDB, &idb_listener, &LPH);
        helper.create(PROCMOD_NODE_NAME);
        return 1;

    case processor_t::ev_term:
        unhook_event_listener(HT_IDB, &idb_listener);
        ioh.ports.clear();
        clr_module_data(data_id);
        return 1;

    case processor_t::ev_newprc:
    {
        int pnum = va_arg(va, int);
        bool keep_cfg = va_argi(va, bool);
        qnotused(pnum);
        if (!keep_cfg)
            inf_set_be(true);
        return 1;
    }

    case processor_t::ev_newfile:
    {
        configure_spu_compiler_and_til();
        char cfgfile[QMAXFILE];
        ioh.get_cfg_filename(cfgfile, sizeof(cfgfile));
        iohandler_t::parse_area_line0_t cb(ioh);
        if (choose_ioport_device2(&ioh.device, cfgfile, &cb))
            ioh.set_device_name(ioh.device.c_str(), IORESP_PORT | IORESP_INT);
        save_to_idb();
        return 1;
    }

    case processor_t::ev_ending_undo:
    case processor_t::ev_oldfile:
        load_from_idb();
        return 1;

    case processor_t::ev_privrange_changed:
        helper.create(PROCMOD_NODE_NAME);
        return 1;

    case processor_t::ev_create_merge_handlers:
    {
        merge_data_t *md = va_arg(va, merge_data_t *);
        create_std_procmod_handlers(*md);
        return 1;
    }

    case processor_t::ev_set_idp_options:
    {
        const char *keyword = va_arg(va, const char *);
        int value_type = va_arg(va, int);
        const void *value = va_arg(va, const void *);
        const char **errmsg = va_arg(va, const char **);
        bool idb_loaded = va_argi(va, bool);
        const char *ret = set_idp_options(keyword, value_type, value, idb_loaded);
        if (ret == IDPOPT_OK)
            return 1;
        if (errmsg != nullptr)
            *errmsg = ret;
        return -1;
    }

    // --- Core Disassembly, Emulation & Output ---
    case processor_t::ev_ana_insn:
        return spu_ana(va_arg(va, insn_t *));

    case processor_t::ev_emu_insn:
        return spu_emu(*va_arg(va, const insn_t *));

    case processor_t::ev_out_mnem:
        spu_out_mnem(*va_arg(va, outctx_t *));
        return 1;

    case processor_t::ev_out_insn:
        out_insn(*va_arg(va, outctx_t *));
        return 1;

    case processor_t::ev_out_operand:
    {
        outctx_t *ctx = va_arg(va, outctx_t *);
        const op_t *op = va_arg(va, const op_t *);
        return out_opnd(*ctx, *op) ? 1 : -1;
    }

    case processor_t::ev_get_autocmt:
    {
        qstring *buf = va_arg(va, qstring *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return get_autocmt(buf, *insn) ? 1 : 0;
    }

    case processor_t::ev_is_align_insn:
        return spu_is_align_insn(va_arg(va, ea_t));

    // --- Call, Return & Function Semantics ---
    case processor_t::ev_is_call_insn:
    {
        const insn_t *insn = va_arg(va, const insn_t *);
        if (insn->itype == SPU_brsl || insn->itype == SPU_brasl ||
            insn->itype == SPU_bisl || insn->itype == SPU_bisled)
            return 1;
        return -1;
    }

    case processor_t::ev_is_ret_insn:
    {
        const insn_t *insn = va_arg(va, const insn_t *);
        uchar flags = va_argi(va, uchar);
        if (insn->itype == SPU_iret)
            return (flags & IRI_RET_LITERALLY) ? -1 : 1;
        if (insn->itype == SPU_bi && insn->Op1.is_reg(rLR))
            return 1;
        if ((flags & IRI_SKIP_RETTARGET) == 0 && (insn->auxpref & SPU_AUX_RET) != 0)
            return 1;
        return -1;
    }

    case processor_t::ev_may_be_func:
    {
        const insn_t *insn = va_arg(va, const insn_t *);
        int state = va_arg(va, int);
        return may_be_func(*insn, state);
    }

    // --- Stack Frames & SP/FP Classification ---
    case processor_t::ev_get_function_retsize:
    {
        int *frsize = va_arg(va, int *);
        ea_t func_ea = va_arg(va, ea_t);
        qnotused(func_ea);
        if (frsize != nullptr)
            *frsize = 0; // SPU uses link register r0 (lr), not stack
        return 1;
    }

    case processor_t::ev_create_function_frame:
    {
        ea_t func_ea = va_arg(va, ea_t);
        func_t *pfn = get_func(func_ea);
        if (pfn != nullptr)
        {
            create_func_frame(pfn);
            return 1;
        }
        return 0;
    }

    case processor_t::ev_create_func_frame:
        create_func_frame(va_arg(va, func_t *));
        return 1;

    case processor_t::ev_is_sp_based:
    {
        int *mode = va_arg(va, int *);
        const insn_t *insn = va_arg(va, const insn_t *);
        const op_t *op = va_arg(va, const op_t *);
        is_sp_based(mode, *insn, *op);
        return 1;
    }

    // --- Switch / Jump Tables ---
    case processor_t::ev_is_switch:
    {
        switch_info_t *si = va_arg(va, switch_info_t *);
        const insn_t *insn = va_arg(va, const insn_t *);
        return spu_is_switch(si, *insn) ? 1 : -1;
    }

    // --- Cell SPU ABI & Type Information (PR_TYPEINFO) ---
    case processor_t::ev_setup_til:
        configure_spu_compiler_and_til();
        return 1;

    case processor_t::ev_max_ptr_size:
        return 4;

    case processor_t::ev_calc_cdecl_purged_bytes:
        return 0;

    case processor_t::ev_get_cc_regs:
    {
        callregs_t *callregs = va_arg(va, callregs_t *);
        callcnv_t cc = va_arg(va, callcnv_t);
        qnotused(cc);
        static int spu_argregs[73];
        static bool inited = false;
        if (!inited)
        {
            for (int i = 0; i < 72; ++i)
                spu_argregs[i] = rR3 + i;
            spu_argregs[72] = -1;
            inited = true;
        }
        callregs->set(ARGREGS_INDEPENDENT, spu_argregs, nullptr);
        return 1;
    }

    case processor_t::ev_calc_retloc:
    {
        argloc_t *retloc = va_arg(va, argloc_t *);
        const tinfo_t *type = va_arg(va, const tinfo_t *);
        cm_t cc = va_arg(va, cm_t);
        return calc_spu_retloc(retloc, *type, cc) ? 1 : -1;
    }

    case processor_t::ev_calc_arglocs:
    {
        func_type_data_t *fti = va_arg(va, func_type_data_t *);
        return calc_spu_arglocs(fti) ? 1 : -1;
    }

    case processor_t::ev_get_reg_info:
    {
        const char **main_regname = va_arg(va, const char **);
        bitrange_t *bitrange = va_arg(va, bitrange_t *);
        const char *regname = va_arg(va, const char *);
        return spu_get_reg_info(main_regname, bitrange, regname);
    }

    default:
        break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Return byte sequences (bi lr = 0x35000000; bid lr = 0x35100000; bie lr = 0x35080000)
// ---------------------------------------------------------------------------
static const uchar retcode_bi_lr[]  = { 0x35, 0x00, 0x00, 0x00 };
static const uchar retcode_bid_lr[] = { 0x35, 0x10, 0x00, 0x00 };
static const uchar retcode_bie_lr[] = { 0x35, 0x08, 0x00, 0x00 };
static const uchar retcode_iret[]   = { 0x35, 0x40, 0x00, 0x00 };

static const bytes_t retcodes[] = {
    { sizeof(retcode_bi_lr),  retcode_bi_lr  },
    { sizeof(retcode_bid_lr), retcode_bid_lr },
    { sizeof(retcode_bie_lr), retcode_bie_lr },
    { sizeof(retcode_iret),   retcode_iret   },
    { 0, nullptr }
};

static const char *const short_names[] = {
    "spu",
    nullptr
};

static const char *const long_names[] = {
    "Cell Broadband Engine SPU",
    nullptr
};

// ---------------------------------------------------------------------------
// Processor Descriptor (LPH)
// ---------------------------------------------------------------------------
idaman processor_t ida_module_data LPH = {
    IDP_INTERFACE_VERSION,
    PLFM_SPU,                                       // id = 59 (drop-in replacement for spu.py)
    PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX |
    PR_RNAMESOK | PR_ALIGN_INSN | PR_TYPEINFO |
    PR_CNDINSNS,                                    // flag
    PR2_IDP_OPTS,                                   // flag2
    8,                                              // cnbits
    8,                                              // dnbits
    short_names,
    long_names,
    assemblers,
    notify,
    reg_names,
    qnumber(reg_names),
    rCS,                                            // reg_first_sreg
    rDS,                                            // reg_last_sreg
    0,                                              // segreg_size
    rCS,                                            // reg_code_sreg
    rDS,                                            // reg_data_sreg
    nullptr,                                        // codestart
    retcodes,                                       // retcodes
    SPU_null,                                       // instruc_start
    SPU_last,                                       // instruc_end
    Instructions,                                   // instruc
    0,                                              // tbyte_size
    { 0, 7, 15, 0 },                                // real_width (32-bit float, 64-bit double)
    SPU_bi,                                         // icode_return
    nullptr                                         // unused_slot
};
