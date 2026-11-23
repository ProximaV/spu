#ifndef __SPU_HPP
#define __SPU_HPP

#pragma warning(disable : 4146)

#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <name.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <problems.hpp>
#include <frame.hpp>
#include <lines.hpp>
#include <loader.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <segregs.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <nalt.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <idaidp.hpp>
#include <iohandler.hpp>

#include "ins.hpp"

#define PROCMOD_NODE_NAME "$ spu"
#define PROCMOD_NAME spu

// Default Cell SPU Local Store Limit Register (256 KB = 0x40000, LSLR = 0x3FFFF)
constexpr uint32 SPU_DEFAULT_LSLR = 0x3FFFFu;

// Register index layout (100% compatible with spudec & legacy spu.py IDBs):
//   0..127   : GPRs (r0=lr, r1=sp, r2..r127; r127=optional ABI FP)
//   128..255 : SPRs (sp0..sp127)
//   256..383 : Channels (ch0..ch127; symbolic names for CBEA 0..30 & PS3 Iso 64..68)
//   384      : CS (virtual code segment)
//   385      : DS (virtual data segment)
enum spu_reg_t : uint16
{
    rLR       = 0,
    rSP       = 1,
    rR2       = 2,
    rR3       = 3,
    rR74      = 74,
    rR80      = 80,
    rFP       = 127,  // SPU ABI optional frame pointer
    rGPR_BASE = 0,
    rSPR_BASE = 128,
    rCH_BASE  = 256,
    rCS       = 384,
    rDS       = 385,
    rREG_COUNT = 386
};

// Operand specval flags (SPU_OP_SIGNED == 0x01 matches spudec FL_SIGNED!)
constexpr uint16 SPU_OP_SIGNED = 0x01; // Signed immediate or displacement
constexpr uint16 SPU_OP_HIGH16 = 0x02; // High 16 bits of paired ilhu+iohl
constexpr uint16 SPU_OP_LOW16  = 0x04; // Low 16 bits of paired ilhu+iohl
constexpr uint16 SPU_OP_BYTE8  = 0x08; // 8-bit immediate (*bi instructions)

// Instruction auxpref flags (bits 0x02..0x10 match legacy spu.py FL_D/E/C/P!)
constexpr uint16 SPU_AUX_D     = 0x02; // 'd' suffix (disable interrupts)
constexpr uint16 SPU_AUX_E     = 0x04; // 'e' suffix (enable interrupts)
constexpr uint16 SPU_AUX_C     = 0x08; // 'c' suffix (syncc - sync channels)
constexpr uint16 SPU_AUX_P     = 0x10; // 'p' suffix (hbrp - inline prefetch)
constexpr uint16 SPU_AUX_RET   = 0x20; // bi lr or conditional return to lr

// Processor option bitmask stored in netnode altval(-1)
constexpr uint32 SPU_OPT_SYM_CHANNELS = 0x0001; // Display symbolic channel names (default ON)
constexpr uint32 SPU_OPT_GNU_REGS     = 0x0002; // Display $0..$127 / $chN / $spN (default OFF)
constexpr uint32 SPU_OPT_SHOW_FALSE_T = 0x0004; // Show non-zero false-target RT in comment (default OFF)
constexpr uint32 SPU_OPT_DEFAULT      = SPU_OPT_SYM_CHANNELS;

struct merge_data_t;
void create_std_procmod_handlers(merge_data_t &md);

// Channel & MFC helpers
const char *spu_channel_sym_name(uint32 ch);
const char *spu_mfc_cmd_name(uint32 cmd);
void format_dftsv_mask(qstring *out, uint32 mask7);

DECLARE_PROC_LISTENER(spu_idb_listener_t, struct spu_t);

struct spu_t : public procmod_t
{
    netnode helper;
    iohandler_t ioh = iohandler_t(helper);
    spu_idb_listener_t idb_listener = spu_idb_listener_t(*this);

    uint32 opt_flags = SPU_OPT_DEFAULT;
    uint32 lslr = SPU_DEFAULT_LSLR;

    virtual ssize_t idaapi on_event(ssize_t msgid, va_list va) override;

    // Configuration persistence
    void load_from_idb();
    void save_to_idb();
    const char *set_idp_options(const char *keyword, int value_type, const void *value, bool idb_loaded);

    // Local Store address wrap helper (overlay-aware for segments >= 0x40000)
    ea_t wrap_ls_addr(ea_t base_ea, sval_t target, bool quadword_align) const;

    // Core processor module phases
    int  spu_ana(insn_t *insn);
    int  spu_emu(const insn_t &insn);
    bool spu_is_switch(switch_info_t *si, const insn_t &insn);
    void create_func_frame(func_t *pfn);
    void is_sp_based(int *mode, const insn_t &insn, const op_t &op) const;
    int  may_be_func(const insn_t &insn, int state) const;
    bool get_autocmt(qstring *buf, const insn_t &insn) const;
    void format_reg_name(qstring *out, uint16 reg) const;
};

extern int data_id;

#endif // __SPU_HPP
