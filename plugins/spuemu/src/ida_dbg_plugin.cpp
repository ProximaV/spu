#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <dbg.hpp>
#include <idd.hpp>
#include <loader.hpp>
#include <bytes.hpp>
#include <segment.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include <nalt.hpp>

#include "disasm.h"
#include "log.h"
#include "machine.h"
#include "module_path.h"

namespace {

constexpr pid_t kPid = 1;
constexpr thid_t kTid = 1;

// Non-intrusive virtual breakpoint placeholder (LS memory stays untouched)
const uchar kSoftBptBytes[4] = { 0x00u, 0x00u, 0x00u, 0x00u };

bool IsSpuProc() {
    const char *proc0 = (PH.psnames != nullptr && PH.psnames[0] != nullptr) ? PH.psnames[0] : nullptr;
#ifdef PLFM_SPU
    if (PH.id == PLFM_SPU) return true;
#endif
    if (PH.id == 59) return true;
    if (proc0 != nullptr && strieq(proc0, "spu")) return true;
    return false;
}

enum RegClassMask : uchar {
    RC_GENERAL  = 1u << 0,
    RC_VECTOR   = 1u << 1,
    RC_FP       = 1u << 2,
    RC_CHANNELS = 1u << 3,
};

const char *const kRegClasses[] = {
    "General registers",
    "Vector registers (128-bit)",
    "Floating-Point (FPSCR)",
    "MFC & Channels",
    nullptr
};

enum RegBackingKind : uint8_t {
    BACK_PC = 0,
    BACK_GPR_WORD,   // Preferred word (slot 0) of r0..r127
    BACK_GPR_VEC,    // Full 128-bit big-endian quadword of r0..r127
    BACK_SRR0,
    BACK_LSLR,
    BACK_IE,
    BACK_CYCLES,
    BACK_FPSCR,
    BACK_MFC_LSA,
    BACK_MFC_EAH,
    BACK_MFC_EAL,
    BACK_MFC_SIZE,
    BACK_MFC_TAGID,
    BACK_MFC_CMD,
    BACK_MFC_TAGMASK,
    BACK_MFC_TAGSTAT,
    BACK_MFC_ATOMIC,
    BACK_EVT_STAT,
    BACK_EVT_MASK,
    BACK_DEC,
    BACK_MACHSTAT,
    BACK_INMBOX_CNT,
    BACK_OUTMBOX_CNT,
};

struct RegBackingDesc {
    RegBackingKind kind;
    uint8_t index;
};

// Dynamic register tables built once on init to keep all 128 vector regs clean
std::vector<std::string> g_reg_name_storage;
std::vector<register_info_t> g_registers;
std::vector<RegBackingDesc> g_reg_backing;

void InitRegisterTables() {
    if (!g_registers.empty()) return;

    auto add_reg = [](const char *name, uint32 flags, uchar rcls, op_dtype_t dt,
                      RegBackingKind kind, uint8_t idx = 0) {
        g_reg_name_storage.emplace_back(name);
        register_info_t ri{};
        ri.name = nullptr;  // filled after storage stabilizes
        ri.flags = flags;
        ri.register_class_mask = rcls;
        ri.dtype = dt;
        ri.bit_strings = nullptr;
        ri.default_bit_strings_mask = 0;
        g_registers.push_back(ri);
        g_reg_backing.push_back(RegBackingDesc{kind, idx});
    };

    // 1. General registers (PC, sp, lr, SRR0, LSLR, IE, r2..r31 preferred words, CYCLES)
    add_reg("PC",     REGISTER_IP | REGISTER_ADDRESS, RC_GENERAL, dt_dword, BACK_PC);
    add_reg("sp",     REGISTER_SP | REGISTER_ADDRESS, RC_GENERAL, dt_dword, BACK_GPR_WORD, 1);
    add_reg("lr",     REGISTER_ADDRESS,               RC_GENERAL, dt_dword, BACK_GPR_WORD, 0);
    add_reg("SRR0",   REGISTER_ADDRESS,               RC_GENERAL, dt_dword, BACK_SRR0);
    add_reg("LSLR",   0,                              RC_GENERAL, dt_dword, BACK_LSLR);
    add_reg("IE",     0,                              RC_GENERAL, dt_byte,  BACK_IE);
    for (uint8_t r = 2; r < 32; ++r) {
        char nb[16];
        qsnprintf(nb, sizeof(nb), "r%u", r);
        add_reg(nb, 0, RC_GENERAL, dt_dword, BACK_GPR_WORD, r);
    }
    add_reg("CYCLES", REGISTER_READONLY,              RC_GENERAL, dt_qword, BACK_CYCLES);

    // 2. Full 128-bit SIMD Vector registers (v0..v127)
    for (uint8_t r = 0; r < 128; ++r) {
        char nb[16];
        qsnprintf(nb, sizeof(nb), "v%u", r);
        add_reg(nb, 0, RC_VECTOR, dt_byte16, BACK_GPR_VEC, r);
    }

    // 3. Floating-Point Status & Control Register (128-bit)
    add_reg("FPSCR", 0, RC_FP, dt_byte16, BACK_FPSCR);

    // 4. MFC & Channel hardware state
    add_reg("MFC_LSA",        REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_LSA);
    add_reg("MFC_EAH",        REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_EAH);
    add_reg("MFC_EAL",        REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_EAL);
    add_reg("MFC_Size",       REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_SIZE);
    add_reg("MFC_TagID",      REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_TAGID);
    add_reg("MFC_Cmd",        REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_CMD);
    add_reg("MFC_TagMask",    REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_TAGMASK);
    add_reg("MFC_TagStat",    REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_TAGSTAT);
    add_reg("MFC_AtomicStat", REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MFC_ATOMIC);
    add_reg("SPU_EventStat",  REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_EVT_STAT);
    add_reg("SPU_EventMask",  REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_EVT_MASK);
    add_reg("SPU_Dec",        0,                 RC_CHANNELS, dt_dword, BACK_DEC);
    add_reg("SPU_MachStat",   REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_MACHSTAT);
    add_reg("SPU_InMboxCnt",  REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_INMBOX_CNT);
    add_reg("SPU_OutMboxCnt", REGISTER_READONLY, RC_CHANNELS, dt_dword, BACK_OUTMBOX_CNT);

    // Bind final stable name pointers
    for (size_t i = 0; i < g_registers.size(); ++i) {
        g_registers[i].name = g_reg_name_storage[i].c_str();
    }
}

int FindRegIdxByExactName(const char *name) {
    if (!name || !*name) return -1;
    for (size_t i = 0; i < g_registers.size(); ++i) {
        if (strieq(g_registers[i].name, name)) return static_cast<int>(i);
    }
    return -1;
}

bool ResolveRegInfo(const char *name, const char **main_regname, bitrange_t *bitrange) {
    if (!name || !*name) return false;
    const int exact = FindRegIdxByExactName(name);
    if (exact >= 0) {
        if (main_regname) *main_regname = g_registers[exact].name;
        if (bitrange) bitrange->reset();  // empty bitrange == whole register (endian-safe!)
        return true;
    }
    if (strieq(name, "r0") || strieq(name, "$0") || strieq(name, "lr")) {
        if (main_regname) *main_regname = "lr";
        if (bitrange) bitrange->reset();
        return true;
    }
    if (strieq(name, "r1") || strieq(name, "$1") || strieq(name, "sp")) {
        if (main_regname) *main_regname = "sp";
        if (bitrange) bitrange->reset();
        return true;
    }
    // Map r32..r127 or $2..$127 -> v32..v127 / r2..r31
    const char *p = name;
    if (*p == 'r' || *p == 'R' || *p == '$') {
        ++p;
        char *end = nullptr;
        const unsigned long n = std::strtoul(p, &end, 10);
        if (end && *end == '\0' && n < 128ul) {
            char nb[16];
            if (n < 32ul) qsnprintf(nb, sizeof(nb), "r%lu", n);
            else          qsnprintf(nb, sizeof(nb), "v%lu", n);
            const int idx = FindRegIdxByExactName(nb);
            if (idx >= 0) {
                if (main_regname) *main_regname = g_registers[idx].name;
                if (bitrange) bitrange->reset();
                return true;
            }
        }
    }
    return false;
}

int FindRegIdxByName(const char *name) {
    const char *canonical = nullptr;
    if (!ResolveRegInfo(name, &canonical, nullptr) || !canonical) return -1;
    return FindRegIdxByExactName(canonical);
}

int WatchTypeFromBpt(bpttype_t type) {
    switch (type) {
    case BPT_WRITE: return 1;
    case BPT_READ:  return 2;
    case BPT_RDWR:  return 3;
    default:        return 0;
    }
}

void IdaLogCallback(const char *line) {
    if (line && *line) msg("%s", line);
}

struct spudbg_plugmod_t;
spudbg_plugmod_t *g_active_plugmod = nullptr;

struct idd_listener_t final : public event_listener_t {
    spudbg_plugmod_t *pm = nullptr;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct idp_spu_listener_t final : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct ui_listener_t final : public event_listener_t {
    bool debugger_selected = false;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct spudbg_plugmod_t final : public plugmod_t {
    spu::SpuMachine machine;
    std::deque<debug_event_t> event_queue;
    std::unordered_set<uint32_t> ida_exec_bpts;
    std::atomic<bool> pause_requested{false};
    bool is_running = false;
    bool attached = false;
    bool hooks_installed = false;
    bool idc_registered = false;
    resume_mode_t resmod = RESMOD_NONE;
    bool ignore_bpt_once = false;
    uint32_t entry_pc = 0;

    idd_listener_t idd_listener;
    idp_spu_listener_t idp_listener;
    ui_listener_t ui_listener;

    spudbg_plugmod_t() {
        g_active_plugmod = this;
        idd_listener.pm = this;
        InstallPromptCallback();
        InstallHooks();
        RegisterIdcFunctions();
    }

    ~spudbg_plugmod_t() override {
        spu::set_log_callback(nullptr);
        UnregisterIdcFunctions();
        UninstallHooks();
        if (g_active_plugmod == this) g_active_plugmod = nullptr;
    }

    bool idaapi run(size_t arg) override;

    void InstallPromptCallback();
    void InstallHooks();
    void UninstallHooks();
    void RegisterIdcFunctions();
    void UnregisterIdcFunctions();
    void ResetSessionState();
    void TryAutoLoadChannelConfig();
    void LoadSegmentsFromIdb();
    uint32_t DetermineEntryPc() const;
    void QueueEvent(const debug_event_t &ev);
    void QueueStopEvent(const spu::StopInfo &stop, bool from_single_step);
    void ReadRegValByIdx(size_t idx, regval_t *out) const;
    uint64_t ReadRegIntByIdx(size_t idx) const;
    void WriteRegValByIdx(size_t idx, const regval_t &val);
    void WriteRegIntAndInvalidate(size_t idx, uint64_t val);
    ssize_t HandleIddEvent(ssize_t code, va_list va);
    ssize_t HandleRexec(const char *cmdline);
};

debugger_t g_debugger = {
    IDD_INTERFACE_VERSION,
    "spuemu",
    DEBUGGER_ID_6811_EMULATOR,
    "spu",
    DBG_FLAG_CAN_CONT_BPT
    | DBG_FLAG_SAFE
    | DBG_FLAG_FAKE_ATTACH
    | DBG_FLAG_NOHOST
    | DBG_FLAG_NOPARAMETERS
    | DBG_FLAG_NOPASSWORD
    | DBG_FLAG_NOSTARTDIR
    | DBG_FLAG_SMALLBLKS
    | DBG_FLAG_ANYSIZE_HWBPT
    | DBG_FLAG_FAST_STEP
    | DBG_HAS_GET_PROCESSES
    | DBG_HAS_ATTACH_PROCESS
    | DBG_HAS_DETACH_PROCESS
    | DBG_HAS_REQUEST_PAUSE
    | DBG_HAS_THREAD_SUSPEND
    | DBG_HAS_THREAD_CONTINUE
    | DBG_HAS_SET_RESUME_MODE
    | DBG_HAS_CHECK_BPT
    | DBG_HAS_REXEC,
    const_cast<const char **>(kRegClasses),
    RC_GENERAL,
    nullptr,  // populated by InitRegisterTables() in init()
    0,
    0x100,
    kSoftBptBytes,
    sizeof(kSoftBptBytes),
    0,
    DBG_RESMOD_STEP_INTO,
};

void spudbg_plugmod_t::InstallPromptCallback() {
    machine.channels.SetPromptCallback([](uint8_t ch, uint32_t pc, uint32_t *val_out) -> bool {
        if (!val_out) return false;
        if (batch) return false;  // In headless/batch mode, park & break cleanly instead of modal dialog
        const char *sym = spu::ChannelSymbolicName(ch);
        qstring answer = "0x0";
        qstring prompt;
        prompt.sprnt("SPU rdch on empty channel ch%u (%s) at PC=0x%05X.\n"
                     "Enter 32-bit value (hex/dec), or Cancel to break into debugger:",
                     ch, sym ? sym : "-", pc);
        if (!ask_str(&answer, HIST_IDENT, "%s", prompt.c_str())) {
            return false;
        }
        char *end = nullptr;
        const unsigned long v = std::strtoul(answer.c_str(), &end, 0);
        if (!end || *end != '\0') return false;
        *val_out = static_cast<uint32_t>(v);
        return true;
    });
}

void spudbg_plugmod_t::InstallHooks() {
    if (!hooks_installed) {
        hook_event_listener(HT_IDD, &idd_listener);
        hook_event_listener(HT_IDP, &idp_listener);
        hook_event_listener(HT_UI,  &ui_listener);
        hooks_installed = true;
    }
}

void spudbg_plugmod_t::UninstallHooks() {
    if (hooks_installed) {
        unhook_event_listener(HT_UI,  &ui_listener);
        unhook_event_listener(HT_IDP, &idp_listener);
        unhook_event_listener(HT_IDD, &idd_listener);
        hooks_installed = false;
    }
}

bool idaapi spudbg_plugmod_t::run(size_t) {
    if (load_debugger("spuemu", false) || load_debugger("spudbg.dll", false)) {
        msg("[spuemu] Selected Cell Broadband Engine SPU emulator debugger backend.\n");
    } else {
        warning("Failed to activate spuemu debugger backend.");
    }
    return true;
}

void spudbg_plugmod_t::LoadSegmentsFromIdb() {
    const int qty = get_segm_qty();
    std::vector<uint8_t> buf;
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->start_ea >= seg->end_ea || seg->is_header_segm()) continue;
        if (seg->type == SEG_XTRN) continue;
        if (seg->start_ea >= spu::SpuMemory::kLocalStoreSize) continue;

        const ea_t clamped_end = std::min<ea_t>(seg->end_ea, spu::SpuMemory::kLocalStoreSize);
        if (clamped_end <= seg->start_ea) continue;

        const uint32_t start = static_cast<uint32_t>(seg->start_ea);
        const size_t seg_size = static_cast<size_t>(clamped_end - seg->start_ea);
        buf.resize(seg_size);
        const ssize_t got = get_bytes(buf.data(), seg_size, seg->start_ea, GMB_READALL);
        if (got <= 0) continue;

        for (size_t off = 0; off < seg_size; ) {
            if (!is_loaded(start + static_cast<uint32_t>(off))) { ++off; continue; }
            size_t run_end = off + 1;
            while (run_end < seg_size && is_loaded(start + static_cast<uint32_t>(run_end))) {
                ++run_end;
            }
            machine.mem.WriteLs(start + static_cast<uint32_t>(off), run_end - off, buf.data() + off);
            off = run_end;
        }
    }
}

uint32_t spudbg_plugmod_t::DetermineEntryPc() const {
    const ea_t start_ip = inf_get_start_ip();
    if (start_ip != BADADDR && start_ip < spu::SpuMemory::kLocalStoreSize) {
        return static_cast<uint32_t>(start_ip) & ~3u;
    }
    for (const char *nm : { "_start", "start", "main" }) {
        const ea_t ea = get_name_ea(BADADDR, nm);
        if (ea != BADADDR && ea < spu::SpuMemory::kLocalStoreSize) {
            return static_cast<uint32_t>(ea) & ~3u;
        }
    }
    if (get_entry_qty() > 0) {
        const ea_t ea = get_entry(get_entry_ordinal(0));
        if (ea != BADADDR && ea < spu::SpuMemory::kLocalStoreSize) {
            return static_cast<uint32_t>(ea) & ~3u;
        }
    }
    return 0u;
}

void spudbg_plugmod_t::TryAutoLoadChannelConfig() {
    const char *idb = get_path(PATH_TYPE_IDB);
    if (idb && *idb) {
        std::string p(idb);
        const size_t dot = p.find_last_of('.');
        const std::string sidecar = (dot != std::string::npos ? p.substr(0, dot) : p) + ".spudev.json";
        if (spu::FileExists(sidecar)) {
            std::string err;
            if (machine.channels.LoadConfigFile(sidecar, &err)) {
                msg("[spuemu] Auto-loaded channel device config: %s\n", sidecar.c_str());
            } else {
                msg("[spuemu WARN] Failed loading %s: %s\n", sidecar.c_str(), err.c_str());
            }
        }
    }
}

void spudbg_plugmod_t::ResetSessionState() {
    machine.mem.ClearLocalStore();
    machine.cpu.ClearBreakpoints();
    machine.mem.ClearWatchpoints();
    LoadSegmentsFromIdb();
    entry_pc = DetermineEntryPc();
    machine.Reset(static_cast<int32_t>(entry_pc));
    TryAutoLoadChannelConfig();
}

void spudbg_plugmod_t::QueueEvent(const debug_event_t &ev) {
    event_queue.push_back(ev);
}

void spudbg_plugmod_t::QueueStopEvent(const spu::StopInfo &stop, bool from_single_step) {
    debug_event_t ev;
    ev.pid = kPid;
    ev.tid = kTid;
    ev.ea = stop.pc;
    ev.handled = true;

    switch (stop.reason) {
    case spu::StopReason::None:
        if (from_single_step) {
            ev.set_eid(STEP);
            ev.ea = machine.cpu.GetPC();
        } else {
            ev.set_eid(PROCESS_SUSPENDED);
        }
        break;

    case spu::StopReason::Breakpoint: {
        bptaddr_t &bpt = ev.set_bpt();
        bpt.hea = BADADDR;
        bpt.kea = BADADDR;
        break;
    }

    case spu::StopReason::Watchpoint: {
        bptaddr_t &bpt = ev.set_bpt();
        bpt.hea = static_cast<ea_t>(stop.detail);
        bpt.kea = BADADDR;
        break;
    }

    case spu::StopReason::StopInsn:
    case spu::StopReason::StopdInsn:
    case spu::StopReason::HaltInsn: {
        excinfo_t &exc = ev.set_exception();
        exc.code = 5;
        exc.can_cont = true;
        exc.ea = stop.pc;
        exc.info = stop.message.c_str();
        break;
    }

    case spu::StopReason::ChannelBreak:
    case spu::StopReason::ChannelStall: {
        const char *sym = spu::ChannelSymbolicName(static_cast<uint8_t>(stop.detail));
        excinfo_t &exc = ev.set_exception();
        exc.code = 5;
        exc.can_cont = true;
        exc.ea = stop.pc;
        exc.info.sprnt("SPU channel ch%u (%s) %s: %s",
                       static_cast<unsigned>(stop.detail),
                       sym ? sym : "-",
                       stop.is_write ? "write" : "read",
                       stop.message.c_str());
        break;
    }

    case spu::StopReason::InvalidInsn: {
        excinfo_t &exc = ev.set_exception();
        exc.code = 4;
        exc.can_cont = true;
        exc.ea = stop.pc;
        exc.info = stop.message.c_str();
        break;
    }
    }

    invalidate_dbgmem_contents(0, spu::SpuMemory::kLocalStoreSize);
    QueueEvent(ev);
}

uint64_t spudbg_plugmod_t::ReadRegIntByIdx(size_t idx) const {
    if (idx >= g_reg_backing.size()) return 0;
    const RegBackingDesc &d = g_reg_backing[idx];
    switch (d.kind) {
    case BACK_PC:          return machine.cpu.GetPC();
    case BACK_GPR_WORD:    return machine.cpu.RegWord(d.index);
    case BACK_GPR_VEC:     return machine.cpu.Reg(d.index).U64(0);
    case BACK_SRR0:        return machine.channels.Events().Srr0();
    case BACK_LSLR:        return machine.mem.Lslr();
    case BACK_IE:          return machine.channels.Events().InterruptEnabled() ? 1u : 0u;
    case BACK_CYCLES:      return machine.cpu.TotalCycles();
    case BACK_FPSCR:       return machine.cpu.Fpscr().U64(0);
    case BACK_MFC_LSA:     return machine.channels.Mfc().Lsa();
    case BACK_MFC_EAH:     return machine.channels.Mfc().Eah();
    case BACK_MFC_EAL:     return machine.channels.Mfc().Eal();
    case BACK_MFC_SIZE:    return machine.channels.Mfc().Size();
    case BACK_MFC_TAGID:   return machine.channels.Mfc().TagId();
    case BACK_MFC_CMD:     return machine.channels.Mfc().LastCmd();
    case BACK_MFC_TAGMASK: return machine.channels.Mfc().TagMask();
    case BACK_MFC_TAGSTAT: return machine.channels.Mfc().TagStatus();
    case BACK_MFC_ATOMIC:  return machine.channels.Mfc().AtomicStatus();
    case BACK_EVT_STAT:    return machine.channels.Events().PendingEvents();
    case BACK_EVT_MASK:    return machine.channels.Events().EventMask();
    case BACK_DEC:         return machine.channels.Events().Decrementer();
    case BACK_MACHSTAT:    return machine.channels.Events().MachStat();
    case BACK_INMBOX_CNT:  return static_cast<uint64_t>(machine.channels.Mailbox().InMbox().size());
    case BACK_OUTMBOX_CNT: return static_cast<uint64_t>(machine.channels.Mailbox().OutMbox().size());
    }
    return 0;
}

void spudbg_plugmod_t::ReadRegValByIdx(size_t idx, regval_t *out) const {
    if (!out || idx >= g_reg_backing.size()) return;
    const RegBackingDesc &d = g_reg_backing[idx];
    if (d.kind == BACK_GPR_VEC) {
        out->set_bytes(machine.cpu.Reg(d.index).b.data(), 16);
        return;
    }
    if (d.kind == BACK_FPSCR) {
        out->set_bytes(machine.cpu.Fpscr().b.data(), 16);
        return;
    }
    out->set_int(ReadRegIntByIdx(idx));
}

void spudbg_plugmod_t::WriteRegValByIdx(size_t idx, const regval_t &val) {
    if (idx >= g_reg_backing.size()) return;
    const RegBackingDesc &d = g_reg_backing[idx];
    if (d.kind == BACK_GPR_VEC) {
        const bytevec_t &bv = val.bytes();
        if (bv.size() >= 16) {
            spu::Quadword q;
            std::memcpy(q.b.data(), bv.begin(), 16);
            machine.cpu.Reg(d.index) = q;
        }
        return;
    }
    if (d.kind == BACK_FPSCR) {
        const bytevec_t &bv = val.bytes();
        if (bv.size() >= 16) {
            spu::Quadword q;
            std::memcpy(q.b.data(), bv.begin(), 16);
            machine.cpu.SetFpscr(q);
        }
        return;
    }
    WriteRegIntAndInvalidate(idx, val.ival);
}

void spudbg_plugmod_t::WriteRegIntAndInvalidate(size_t idx, uint64_t val) {
    if (idx >= g_reg_backing.size()) return;
    const RegBackingDesc &d = g_reg_backing[idx];
    switch (d.kind) {
    case BACK_PC:       machine.cpu.SetPC(static_cast<uint32_t>(val)); break;
    case BACK_GPR_WORD: machine.cpu.SetRegWord(d.index, static_cast<uint32_t>(val)); break;
    case BACK_SRR0:     machine.channels.Events().SetSrr0(static_cast<uint32_t>(val)); break;
    case BACK_LSLR:     machine.mem.SetLslr(static_cast<uint32_t>(val)); break;
    case BACK_IE:       machine.channels.Events().SetInterruptEnable((val & 1u) != 0); break;
    case BACK_DEC:      machine.channels.Events().SetDecrementer(static_cast<uint32_t>(val)); break;
    default:            break;
    }
    invalidate_dbg_state(DBGINV_REGS);
}

ssize_t spudbg_plugmod_t::HandleRexec(const char *cmdline) {
    std::string out;
    const char *cmd = (cmdline && *cmdline) ? cmdline : "help";
    machine.ExecuteCommand(cmd, out);
    if (!out.empty()) msg("%s\n", out.c_str());
    invalidate_dbgmem_contents(0, spu::SpuMemory::kLocalStoreSize);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    return 0;
}

ssize_t spudbg_plugmod_t::HandleIddEvent(ssize_t code, va_list va) {
    switch (code) {
    case debugger_t::ev_init_debugger:
        va_arg(va, const char *);
        va_arg(va, int);
        va_arg(va, const char *);
        va_arg(va, qstring *);
        spu::set_log_callback(IdaLogCallback);
        event_queue.clear();
        ida_exec_bpts.clear();
        pause_requested.store(false);
        is_running = false;
        attached = false;
        return DRC_OK;

    case debugger_t::ev_term_debugger:
        spu::set_log_callback(nullptr);
        event_queue.clear();
        ida_exec_bpts.clear();
        is_running = false;
        attached = false;
        return DRC_OK;

    case debugger_t::ev_get_processes: {
        procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
        va_arg(va, qstring *);
        if (procs) {
            process_info_t &pi = procs->push_back();
            pi.pid = kPid;
            pi.name = "Cell Broadband Engine SPU Emulator";
        }
        return DRC_OK;
    }

    case debugger_t::ev_start_process: {
        const char *path = va_arg(va, const char *);
        va_arg(va, const char *);
        va_arg(va, const char *);
        va_arg(va, uint32);
        const char *input_path = va_arg(va, const char *);
        va_arg(va, uint32);
        va_arg(va, qstring *);
        va_arg(va, launch_env_t *);

        ResetSessionState();
        event_queue.clear();
        ida_exec_bpts.clear();
        pause_requested.store(false);
        is_running = false;
        attached = true;
        resmod = RESMOD_NONE;
        ignore_bpt_once = false;

        debug_event_t ev;
        ev.set_eid(PROCESS_STARTED);
        ev.pid = kPid;
        ev.tid = kTid;
        ev.ea = entry_pc;
        ev.handled = true;
        ev.modinfo().name = (input_path && *input_path) ? input_path : (path && *path ? path : "spu.elf");
        ev.modinfo().base = 0;
        ev.modinfo().size = spu::SpuMemory::kLocalStoreSize;
        ev.modinfo().rebase_to = BADADDR;
        QueueEvent(ev);

        debug_event_t susp;
        susp.set_eid(PROCESS_SUSPENDED);
        susp.pid = kPid;
        susp.tid = kTid;
        susp.ea = entry_pc;
        susp.handled = true;
        QueueEvent(susp);
        return DRC_OK;
    }

    case debugger_t::ev_attach_process: {
        va_arg(va, pid_t);
        va_arg(va, int);
        va_arg(va, uint32);
        va_arg(va, qstring *);

        ResetSessionState();
        event_queue.clear();
        ida_exec_bpts.clear();
        pause_requested.store(false);
        is_running = false;
        attached = true;
        resmod = RESMOD_NONE;
        ignore_bpt_once = false;

        debug_event_t ev;
        ev.set_eid(PROCESS_STARTED);
        ev.pid = kPid;
        ev.tid = kTid;
        ev.ea = entry_pc;
        ev.handled = true;
        ev.modinfo().name = "spu.elf";
        ev.modinfo().base = 0;
        ev.modinfo().size = spu::SpuMemory::kLocalStoreSize;
        ev.modinfo().rebase_to = BADADDR;
        QueueEvent(ev);
        return DRC_OK;
    }

    case debugger_t::ev_detach_process:
    case debugger_t::ev_exit_process: {
        va_arg(va, qstring *);
        is_running = false;
        attached = false;
        debug_event_t ev;
        ev.set_exit_code(PROCESS_EXITED, 0);
        ev.pid = kPid;
        ev.tid = kTid;
        ev.ea = machine.cpu.GetPC();
        ev.handled = true;
        QueueEvent(ev);
        return DRC_OK;
    }

    case debugger_t::ev_get_debapp_attrs: {
        debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
        if (out_pattrs) {
            out_pattrs->addrsize = 4;
            out_pattrs->platform = "spu";
            out_pattrs->is_be = true;
        }
        return DRC_OK;
    }

    case debugger_t::ev_rebase_if_required_to:
        va_arg(va, ea_t);
        return DRC_OK;

    case debugger_t::ev_request_pause:
        va_arg(va, qstring *);
        pause_requested.store(true);
        return DRC_OK;

    case debugger_t::ev_set_resume_mode:
        va_arg(va, thid_t);
        resmod = static_cast<resume_mode_t>(va_arg(va, int));
        va_arg(va, qstring *);
        return DRC_OK;

    case debugger_t::ev_resume: {
        const debug_event_t *ev = va_arg(va, const debug_event_t *);
        if (attached) {
            pause_requested.store(false);
            if (ev && ev->eid() == PROCESS_STARTED && !event_queue.empty()) {
                is_running = false;
            } else {
                is_running = true;
                ignore_bpt_once = true;
            }
        }
        return DRC_OK;
    }

    case debugger_t::ev_get_debug_event: {
        gdecode_t *out_code = va_arg(va, gdecode_t *);
        debug_event_t *event = va_arg(va, debug_event_t *);
        const int timeout_ms = va_arg(va, int);
        if (!out_code || !event) return DRC_FAILED;

        if (event_queue.empty() && is_running) {
            if (resmod == RESMOD_INTO) {
                const spu::StopInfo stop = machine.Step(ignore_bpt_once);
                ignore_bpt_once = false;
                is_running = false;
                resmod = RESMOD_NONE;
                QueueStopEvent(stop, true);
            } else {
                const spu::StopInfo stop = machine.RunSteps(100000ULL, ignore_bpt_once, &pause_requested);
                ignore_bpt_once = false;
                if (pause_requested.exchange(false)) {
                    is_running = false;
                    QueueStopEvent(spu::StopInfo{spu::StopReason::None, machine.cpu.GetPC(), 0, false, ""}, false);
                } else if (stop.reason != spu::StopReason::None) {
                    is_running = false;
                    QueueStopEvent(stop, false);
                }
            }
        }

        if (event_queue.empty()) {
            if (!is_running && timeout_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 10)));
            }
            *out_code = GDE_NO_EVENT;
            return DRC_OK;
        }

        *event = event_queue.front();
        event_queue.pop_front();
        if (event->eid() == PROCESS_SUSPENDED) is_running = false;
        *out_code = event_queue.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
        return DRC_OK;
    }

    case debugger_t::ev_thread_suspend:
    case debugger_t::ev_thread_continue:
        va_arg(va, thid_t);
        va_arg(va, qstring *);
        return DRC_OK;

    case debugger_t::ev_read_registers: {
        va_arg(va, thid_t);
        const int clsmask = va_arg(va, int);
        regval_t *values = va_arg(va, regval_t *);
        va_arg(va, qstring *);
        if (!values) return DRC_FAILED;
        for (size_t i = 0; i < g_registers.size(); ++i) {
            if (clsmask == 0 || (g_registers[i].register_class_mask & clsmask) != 0) {
                ReadRegValByIdx(i, &values[i]);
            }
        }
        return DRC_OK;
    }

    case debugger_t::ev_write_register: {
        va_arg(va, thid_t);
        const int regidx = va_arg(va, int);
        const regval_t *value = va_arg(va, const regval_t *);
        va_arg(va, qstring *);
        if (!value || regidx < 0 || static_cast<size_t>(regidx) >= g_registers.size()) {
            return DRC_FAILED;
        }
        WriteRegValByIdx(static_cast<size_t>(regidx), *value);
        invalidate_dbg_state(DBGINV_REGS);
        return DRC_OK;
    }

    case debugger_t::ev_get_memory_info: {
        meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
        va_arg(va, qstring *);
        if (!ranges) return DRC_FAILED;
        ranges->qclear();
        memory_info_t &mi = ranges->push_back();
        mi.start_ea = 0;
        mi.end_ea = spu::SpuMemory::kLocalStoreSize;
        mi.name = "LOCAL_STORE";
        mi.sclass = "CODE";
        mi.sbase = 0;
        mi.bitness = 1;  // 32-bit addressing
        mi.perm = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC;
        return DRC_OK;
    }

    case debugger_t::ev_read_memory: {
        size_t *nbytes = va_arg(va, size_t *);
        const ea_t ea = va_arg(va, ea_t);
        void *buffer = va_arg(va, void *);
        const size_t size = va_arg(va, size_t);
        va_arg(va, qstring *);
        if (!nbytes || !buffer) return DRC_FAILED;
        if (size == 0) { *nbytes = 0; return DRC_OK; }
        if (ea >= spu::SpuMemory::kLocalStoreSize) { *nbytes = 0; return DRC_FAILED; }
        const size_t avail = static_cast<size_t>(spu::SpuMemory::kLocalStoreSize - ea);
        const size_t to_read = std::min(size, avail);
        machine.mem.ReadLs(static_cast<uint32_t>(ea), to_read, buffer);
        *nbytes = to_read;
        return DRC_OK;
    }

    case debugger_t::ev_write_memory: {
        size_t *nbytes = va_arg(va, size_t *);
        const ea_t ea = va_arg(va, ea_t);
        const void *buffer = va_arg(va, const void *);
        const size_t size = va_arg(va, size_t);
        va_arg(va, qstring *);
        if (!nbytes || !buffer) return DRC_FAILED;
        if (size == 0) { *nbytes = 0; return DRC_OK; }
        if (ea >= spu::SpuMemory::kLocalStoreSize) { *nbytes = 0; return DRC_FAILED; }
        const size_t avail = static_cast<size_t>(spu::SpuMemory::kLocalStoreSize - ea);
        const size_t to_write = std::min(size, avail);
        machine.mem.WriteLs(static_cast<uint32_t>(ea), to_write, buffer);
        *nbytes = to_write;
        return DRC_OK;
    }

    case debugger_t::ev_check_bpt: {
        int *bptvc = va_arg(va, int *);
        const bpttype_t type = va_arg(va, bpttype_t);
        const ea_t ea = va_arg(va, ea_t);
        va_arg(va, int);
        if (bptvc) {
            if (ea >= spu::SpuMemory::kLocalStoreSize) {
                *bptvc = BPT_BAD_ADDR;
            } else {
                switch (type) {
                case BPT_SOFT:
                case BPT_EXEC:
                case BPT_DEFAULT:
                case BPT_WRITE:
                case BPT_READ:
                case BPT_RDWR:
                    *bptvc = BPT_OK;
                    break;
                default:
                    *bptvc = BPT_BAD_TYPE;
                    break;
                }
            }
        }
        return DRC_OK;
    }

    case debugger_t::ev_update_bpts: {
        int *nbpts = va_arg(va, int *);
        update_bpt_info_t *bpts = va_arg(va, update_bpt_info_t *);
        const int nadd = va_arg(va, int);
        const int ndel = va_arg(va, int);
        va_arg(va, qstring *);
        int count = 0;
        for (int i = 0; i < nadd + ndel; ++i) {
            update_bpt_info_t &b = bpts[i];
            if (b.code == BPT_SKIP) continue;
            if (b.ea >= spu::SpuMemory::kLocalStoreSize) { b.code = BPT_BAD_ADDR; continue; }
            const bool is_add = i < nadd;
            const uint32_t ea = static_cast<uint32_t>(b.ea);
            if (b.type == BPT_SOFT || b.type == BPT_EXEC || b.type == BPT_DEFAULT) {
                if (is_add) {
                    if (b.type == BPT_SOFT || b.type == BPT_DEFAULT) {
                        b.orgbytes.resize(4);
                        machine.mem.ReadLs(ea, 4, b.orgbytes.begin());
                    }
                    machine.cpu.AddBreakpoint(ea);
                    ida_exec_bpts.insert(ea & ~3u);
                } else {
                    machine.cpu.RemoveBreakpoint(ea);
                    ida_exec_bpts.erase(ea & ~3u);
                }
                b.code = BPT_OK;
                ++count;
            } else {
                const int wt = WatchTypeFromBpt(b.type);
                const uint32_t wsize = b.size > 0 ? static_cast<uint32_t>(b.size) : 4u;
                if (wt != 0) {
                    if (is_add) machine.mem.AddWatchpoint(ea, wsize, wt);
                    else machine.mem.RemoveWatchpoint(ea, wsize, wt);
                    b.code = BPT_OK;
                    ++count;
                } else {
                    b.code = BPT_BAD_TYPE;
                }
            }
        }
        if (nbpts) *nbpts = count;
        return DRC_OK;
    }

    case debugger_t::ev_rexec:
        return HandleRexec(va_arg(va, const char *));

    default:
        break;
    }
    return DRC_NONE;
}

ssize_t idaapi idd_listener_t::on_event(ssize_t code, va_list va) {
    return pm ? pm->HandleIddEvent(code, va) : DRC_NONE;
}

ssize_t idaapi idp_spu_listener_t::on_event(ssize_t code, va_list va) {
    if (!IsSpuProc()) return 0;

    switch (code) {
    case processor_t::ev_get_reg_info: {
        const char **main_regname = va_arg(va, const char **);
        bitrange_t *bitrange = va_arg(va, bitrange_t *);
        const char *regname = va_arg(va, const char *);
        if (ResolveRegInfo(regname, main_regname, bitrange)) {
            return 1;
        }
        return 0;
    }

    case processor_t::ev_calc_step_over: {
        ea_t *target = va_arg(va, ea_t *);
        const ea_t ip = va_arg(va, ea_t);
        if (!target || ip == BADADDR) return 0;
        insn_t ins;
        if (decode_insn(&ins, ip) <= 0) return 0;
        qstring mnem;
        print_insn_mnem(&mnem, ip);
        if (strnicmp(mnem.c_str(), "brsl", 4) == 0 ||
            strnicmp(mnem.c_str(), "brasl", 5) == 0 ||
            strnicmp(mnem.c_str(), "bisl", 4) == 0) {
            *target = ip + ins.size;
            return 1;
        }
        *target = BADADDR;
        return 1;
    }
    default:
        break;
    }
    return 0;
}

ssize_t idaapi ui_listener_t::on_event(ssize_t code, va_list) {
    if (IsSpuProc() &&
        (code == ui_database_inited || code == ui_ready_to_run) &&
        !debugger_selected) {
        if (load_debugger("spuemu", false) || load_debugger("spudbg.dll", false)) {
            debugger_selected = true;
        }
    }
    return 0;
}

// ============================================================================
// IDC / IDAPython Scripting Helpers (spudbg_*)
// ============================================================================
error_t idaapi idc_spudbg_start(idc_value_t *, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    pm->ResetSessionState();
    pm->event_queue.clear();
    pm->ida_exec_bpts.clear();
    pm->pause_requested.store(false);
    pm->is_running = false;
    pm->attached = true;
    pm->resmod = RESMOD_NONE;
    pm->ignore_bpt_once = false;
    r->set_long(static_cast<sval_t>(pm->entry_pc));
    return eOk;
}

error_t idaapi idc_spudbg_stop(idc_value_t *, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    pm->is_running = false;
    pm->attached = false;
    pm->event_queue.clear();
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_step(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const uint64_t cnt = argv[0].num > 0 ? static_cast<uint64_t>(argv[0].num) : 1ULL;
    if (cnt == 1) pm->machine.Step(true);
    else pm->machine.RunSteps(cnt, true, &pm->pause_requested);
    invalidate_dbgmem_contents(0, spu::SpuMemory::kLocalStoreSize);
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(static_cast<sval_t>(pm->machine.cpu.GetPC()));
    return eOk;
}

error_t idaapi idc_spudbg_run_to(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const uint32_t target = static_cast<uint32_t>(argv[0].num) & pm->machine.mem.Lslr() & ~3u;
    const uint64_t max_steps = argv[1].num > 0 ? static_cast<uint64_t>(argv[1].num) : 1000000ULL;
    for (uint64_t i = 0; i < max_steps; ++i) {
        const auto stop = pm->machine.Step(i == 0);
        if (pm->machine.cpu.GetPC() == target || stop.reason != spu::StopReason::None) break;
    }
    invalidate_dbgmem_contents(0, spu::SpuMemory::kLocalStoreSize);
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(static_cast<sval_t>(pm->machine.cpu.GetPC()));
    return eOk;
}

error_t idaapi idc_spudbg_get_reg(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) { r->set_long(-1); return eOk; }
    r->set_long(static_cast<sval_t>(pm->ReadRegIntByIdx(static_cast<size_t>(idx))));
    return eOk;
}

error_t idaapi idc_spudbg_set_reg(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) { r->set_long(0); return eOk; }
    pm->WriteRegIntAndInvalidate(static_cast<size_t>(idx), static_cast<uint64_t>(argv[1].num));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_get_vec(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_string(""); return eOk; }
    const uint8_t regno = static_cast<uint8_t>(argv[0].num & 0x7F);
    const auto &q = pm->machine.cpu.Reg(regno);
    char buf[48];
    qsnprintf(buf, sizeof(buf), "%08X %08X %08X %08X", q.U32(0), q.U32(1), q.U32(2), q.U32(3));
    r->set_string(buf);
    return eOk;
}

error_t idaapi idc_spudbg_set_vec(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const uint8_t regno = static_cast<uint8_t>(argv[0].num & 0x7F);
    pm->machine.cpu.Reg(regno) = spu::Quadword::FromWords(
        static_cast<uint32_t>(argv[1].num), static_cast<uint32_t>(argv[2].num),
        static_cast<uint32_t>(argv[3].num), static_cast<uint32_t>(argv[4].num));
    invalidate_dbg_state(DBGINV_REGS);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_read_u32(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(-1); return eOk; }
    uint8_t b[4] = {};
    pm->machine.mem.ReadLs(static_cast<uint32_t>(argv[0].num), 4, b);
    const uint32_t w = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
                       (static_cast<uint32_t>(b[2]) << 8) | b[3];
    r->set_long(static_cast<sval_t>(w));
    return eOk;
}

error_t idaapi idc_spudbg_write_u32(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const uint32_t addr = static_cast<uint32_t>(argv[0].num);
    const uint32_t w = static_cast<uint32_t>(argv[1].num);
    const uint8_t b[4] = {
        static_cast<uint8_t>(w >> 24), static_cast<uint8_t>(w >> 16),
        static_cast<uint8_t>(w >> 8), static_cast<uint8_t>(w)
    };
    pm->machine.mem.WriteLs(addr, 4, b);
    invalidate_dbgmem_contents(addr & spu::SpuMemory::kDefaultLslr, 4);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_map_ea(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    const bool ok = pm->machine.mem.MapMainMemory(
        static_cast<uint64_t>(argv[0].num),
        static_cast<size_t>(argv[1].num),
        argv[2].c_str());
    r->set_long(ok ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_load_devices(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    std::string err;
    const bool ok = pm->machine.channels.LoadConfigFile(argv[0].c_str(), &err);
    if (!ok) msg("[spuemu ERROR] load_devices: %s\n", err.c_str());
    r->set_long(ok ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_save_devices(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    std::string err;
    const bool ok = pm->machine.channels.SaveConfigFile(argv[0].c_str(), &err);
    if (!ok) msg("[spuemu ERROR] save_devices: %s\n", err.c_str());
    r->set_long(ok ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_ch_push(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    uint8_t ch = 0;
    if (!pm || !spu::ParseChannelId(argv[0].c_str(), &ch)) { r->set_long(0); return eOk; }
    r->set_long(pm->machine.channels.PushInput(ch, static_cast<uint32_t>(argv[1].num)) ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_ch_pop(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    uint8_t ch = 0;
    uint32_t val = 0;
    if (!pm || !spu::ParseChannelId(argv[0].c_str(), &ch) ||
        !pm->machine.channels.PopOutput(ch, &val)) {
        r->set_long(-1);
        return eOk;
    }
    r->set_long(static_cast<sval_t>(val));
    return eOk;
}

error_t idaapi idc_spudbg_ch_set(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    uint8_t ch = 0;
    if (!pm || !spu::ParseChannelId(argv[0].c_str(), &ch)) { r->set_long(0); return eOk; }
    r->set_long(pm->machine.channels.SetValue(ch, static_cast<uint32_t>(argv[1].num)) ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_ch_set_count(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    uint8_t ch = 0;
    if (!pm || !spu::ParseChannelId(argv[0].c_str(), &ch)) { r->set_long(0); return eOk; }
    r->set_long(pm->machine.channels.SetCount(ch, static_cast<uint32_t>(argv[1].num)) ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_ch_set_break(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    std::string out;
    const std::string cmd = std::string("ch break ") + argv[0].c_str() + " " + argv[1].c_str();
    r->set_long(pm->machine.ExecuteCommand(cmd, out) ? 1 : 0);
    return eOk;
}

error_t idaapi idc_spudbg_ch_attach(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    std::string out;
    std::string cmd = std::string("ch attach ") + argv[0].c_str() + " " + argv[1].c_str();
    if (argv[2].c_str() && argv[2].c_str()[0] != '\0') {
        cmd += " ";
        cmd += argv[2].c_str();
    }
    r->set_long(pm->machine.ExecuteCommand(cmd, out) ? 1 : 0);
    return eOk;
}

// Attach an IDAPython ("py:my_func") or IDC ("my_idc_func") callback to a channel!
// Handler signature: fn(ch: int, op: str ('R'|'W'|'C'), val: int) -> int
// Returning a negative value signals ChannelStatus::Break.
error_t idaapi idc_spudbg_set_ch_callback(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    uint8_t ch = 0;
    if (!pm || !spu::ParseChannelId(argv[0].c_str(), &ch)) { r->set_long(0); return eOk; }
    const std::string spec = argv[1].c_str() ? argv[1].c_str() : "";
    if (spec.empty()) {
        pm->machine.channels.DetachDevice(ch);
        r->set_long(1);
        return eOk;
    }

    const bool is_python = (spec.rfind("py:", 0) == 0);
    const std::string fn_name = is_python ? spec.substr(3) : spec;

    auto dev = std::make_shared<spu::CallbackChannelDevice>(
        spec,
        [is_python, fn_name](uint8_t cid, char op, uint32_t in_val, uint32_t *val_out) -> spu::ChannelStatus {
            qstring expr;
            expr.sprnt("%s(%u, \"%c\", 0x%X)", fn_name.c_str(), static_cast<unsigned>(cid), op, in_val);
            idc_value_t rv;
            qstring errbuf;
            bool ok = false;
            if (is_python) {
                extlang_object_t py = find_extlang_by_name("Python");
                if (py != nullptr && py->eval_expr != nullptr) {
                    ok = py->eval_expr(&rv, BADADDR, expr.c_str(), &errbuf);
                }
            } else {
                ok = eval_idc_expr(&rv, BADADDR, expr.c_str(), &errbuf);
            }
            if (!ok) {
                msg("[spuemu ERROR] channel callback %s failed: %s\n", fn_name.c_str(), errbuf.c_str());
                return spu::ChannelStatus::Break;
            }
            const int64_t res = (rv.vtype == VT_INT64) ? rv.i64 : static_cast<int64_t>(rv.num);
            if (res < 0) return spu::ChannelStatus::Break;
            if (val_out) *val_out = static_cast<uint32_t>(res & 0xFFFFFFFFULL);
            return spu::ChannelStatus::Ok;
        });

    pm->machine.channels.AttachDevice(ch, dev);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_add_bpt(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    pm->machine.cpu.AddBreakpoint(static_cast<uint32_t>(argv[0].num));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_del_bpt(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_long(0); return eOk; }
    pm->machine.cpu.RemoveBreakpoint(static_cast<uint32_t>(argv[0].num));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_spudbg_exec(idc_value_t *argv, idc_value_t *r) {
    auto *pm = g_active_plugmod;
    if (!pm) { r->set_string("ERROR: spudbg plugmod not active"); return eOk; }
    std::string out;
    pm->machine.ExecuteCommand(argv[0].c_str(), out);
    invalidate_dbgmem_contents(0, spu::SpuMemory::kLocalStoreSize);
    invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    r->set_string(out.c_str());
    return eOk;
}

const char kArgsNone[]      = { 0 };
const char kArgsLong[]      = { VT_LONG, 0 };
const char kArgsStr[]       = { VT_STR, 0 };
const char kArgsStrStr[]    = { VT_STR, VT_STR, 0 };
const char kArgsStrStrStr[] = { VT_STR, VT_STR, VT_STR, 0 };
const char kArgsStrLong[]   = { VT_STR, VT_LONG, 0 };
const char kArgsLongLong[]  = { VT_LONG, VT_LONG, 0 };
const char kArgsLongLongStr[] = { VT_LONG, VT_LONG, VT_STR, 0 };
const char kArgs5Long[]     = { VT_LONG, VT_LONG, VT_LONG, VT_LONG, VT_LONG, 0 };

const ext_idcfunc_t kIdcFuncs[] = {
    { "spudbg_start",           idc_spudbg_start,           kArgsNone,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_stop",            idc_spudbg_stop,            kArgsNone,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_step",            idc_spudbg_step,            kArgsLong,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_run_to",          idc_spudbg_run_to,          kArgsLongLong,    nullptr, 0, EXTFUN_BASE },
    { "spudbg_get_reg",         idc_spudbg_get_reg,         kArgsStr,         nullptr, 0, EXTFUN_BASE },
    { "spudbg_set_reg",         idc_spudbg_set_reg,         kArgsStrLong,     nullptr, 0, EXTFUN_BASE },
    { "spudbg_get_vec",         idc_spudbg_get_vec,         kArgsLong,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_set_vec",         idc_spudbg_set_vec,         kArgs5Long,       nullptr, 0, EXTFUN_BASE },
    { "spudbg_read_u32",        idc_spudbg_read_u32,        kArgsLong,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_write_u32",       idc_spudbg_write_u32,       kArgsLongLong,    nullptr, 0, EXTFUN_BASE },
    { "spudbg_map_ea",          idc_spudbg_map_ea,          kArgsLongLongStr, nullptr, 0, EXTFUN_BASE },
    { "spudbg_load_devices",    idc_spudbg_load_devices,    kArgsStr,         nullptr, 0, EXTFUN_BASE },
    { "spudbg_save_devices",    idc_spudbg_save_devices,    kArgsStr,         nullptr, 0, EXTFUN_BASE },
    { "spudbg_ch_push",         idc_spudbg_ch_push,         kArgsStrLong,     nullptr, 0, EXTFUN_BASE },
    { "spudbg_ch_pop",          idc_spudbg_ch_pop,          kArgsStr,         nullptr, 0, EXTFUN_BASE },
    { "spudbg_ch_set",          idc_spudbg_ch_set,          kArgsStrLong,     nullptr, 0, EXTFUN_BASE },
    { "spudbg_ch_set_count",    idc_spudbg_ch_set_count,    kArgsStrLong,     nullptr, 0, EXTFUN_BASE },
    { "spudbg_ch_set_break",    idc_spudbg_ch_set_break,    kArgsStrStr,      nullptr, 0, EXTFUN_BASE },
    { "spudbg_ch_attach",       idc_spudbg_ch_attach,       kArgsStrStrStr,   nullptr, 0, EXTFUN_BASE },
    { "spudbg_set_ch_callback", idc_spudbg_set_ch_callback, kArgsStrStr,      nullptr, 0, EXTFUN_BASE },
    { "spudbg_add_bpt",         idc_spudbg_add_bpt,         kArgsLong,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_del_bpt",         idc_spudbg_del_bpt,         kArgsLong,        nullptr, 0, EXTFUN_BASE },
    { "spudbg_exec",            idc_spudbg_exec,            kArgsStr,         nullptr, 0, EXTFUN_BASE },
};

void spudbg_plugmod_t::RegisterIdcFunctions() {
    if (!idc_registered) {
        for (const auto &fn : kIdcFuncs) add_idc_func(fn);
        idc_registered = true;
    }
}

void spudbg_plugmod_t::UnregisterIdcFunctions() {
    if (idc_registered) {
        for (const auto &fn : kIdcFuncs) del_idc_func(fn.name);
        idc_registered = false;
    }
}

plugmod_t *idaapi init(void) {
    if (!IsSpuProc()) return PLUGIN_SKIP;
    InitRegisterTables();
    g_debugger.registers = g_registers.data();
    g_debugger.nregisters = static_cast<int>(g_registers.size());
    const char *proc0 = (PH.psnames != nullptr && PH.psnames[0] != nullptr) ? PH.psnames[0] : nullptr;
    if (proc0 != nullptr) g_debugger.processor = proc0;
    dbg = &g_debugger;
    return new spudbg_plugmod_t();
}

}  // namespace

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_DBG | PLUGIN_PROC | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Integrated Cell SPU Emulator Debugger",
    "In-process Cell Broadband Engine SPU emulator debugger with pluggable channel devices (spuemu).",
    "Cell SPU spuemu",
    ""
};
