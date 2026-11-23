#include "machine.h"

#include "disasm.h"
#include "log.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

namespace spu {

namespace {

std::vector<std::string> SplitArgs(const std::string &line) {
    std::vector<std::string> out;
    size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && std::isspace(static_cast<unsigned char>(line[i]))) ++i;
        if (i >= line.size()) break;
        std::string tok;
        if (line[i] == '"') {
            ++i;
            while (i < line.size() && line[i] != '"') {
                if (line[i] == '\\' && i + 1 < line.size()) ++i;
                tok.push_back(line[i++]);
            }
            if (i < line.size() && line[i] == '"') ++i;
        } else {
            while (i < line.size() && !std::isspace(static_cast<unsigned char>(line[i]))) {
                tok.push_back(line[i++]);
            }
        }
        out.push_back(std::move(tok));
    }
    return out;
}

bool ParseU64(const std::string &s, uint64_t *out) {
    if (s.empty() || !out) return false;
    char *end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 0);
    if (!end || *end != '\0') return false;
    *out = static_cast<uint64_t>(v);
    return true;
}

bool ParseU32(const std::string &s, uint32_t *out) {
    uint64_t v = 0;
    if (!ParseU64(s, &v)) return false;
    *out = static_cast<uint32_t>(v);
    return true;
}

bool ParseRegId(const std::string &tok, uint8_t *out_reg) {
    if (tok.empty() || !out_reg) return false;
    std::string s = tok;
    for (char &c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (s == "lr") { *out_reg = 0; return true; }
    if (s == "sp") { *out_reg = 1; return true; }
    if (!s.empty() && (s[0] == 'r' || s[0] == '$')) s.erase(s.begin());
    uint32_t v = 0;
    if (ParseU32(s, &v) && v < 128u) {
        *out_reg = static_cast<uint8_t>(v);
        return true;
    }
    return false;
}

uint16_t ReadBe16(const uint8_t *p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t ReadBe32(const uint8_t *p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

std::string FormatQuadword(const Quadword &q) {
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%08X %08X %08X %08X",
                  q.U32(0), q.U32(1), q.U32(2), q.U32(3));
    return buf;
}

}  // namespace

SpuMachine::SpuMachine()
    : mem(),
      channels(&mem),
      cpu(&mem, &channels) {}

void SpuMachine::Reset(int32_t entry_pc_override) {
    mem.Reset();
    channels.ResetState();
    const uint32_t ep = (entry_pc_override >= 0)
                            ? static_cast<uint32_t>(entry_pc_override)
                            : last_entry_pc;
    last_entry_pc = ep & mem.Lslr() & ~3u;
    cpu.Reset(last_entry_pc);
}

bool SpuMachine::LoadElfFile(const std::string &path, uint32_t *entry_out, std::string *err_out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        if (err_out) *err_out = "Cannot open ELF file: " + path;
        return false;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)),
                              std::istreambuf_iterator<char>());
    if (data.size() < 52 || data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        if (err_out) *err_out = "Not a valid ELF file";
        return false;
    }
    if (data[4] != 1 || data[5] != 2) {  // ELFCLASS32, ELFDATA2MSB
        if (err_out) *err_out = "Expected 32-bit big-endian SPU ELF";
        return false;
    }
    const uint16_t e_machine = ReadBe16(&data[18]);
    if (e_machine != 23u) {  // EM_SPU = 23
        if (err_out) *err_out = "ELF machine type is not EM_SPU (23)";
        return false;
    }

    const uint32_t e_entry = ReadBe32(&data[24]);
    const uint32_t e_phoff = ReadBe32(&data[28]);
    const uint16_t e_phentsize = ReadBe16(&data[42]);
    const uint16_t e_phnum = ReadBe16(&data[44]);

    mem.ClearLocalStore();
    for (uint16_t i = 0; i < e_phnum; ++i) {
        const size_t off = static_cast<size_t>(e_phoff) + static_cast<size_t>(i) * e_phentsize;
        if (off + 32 > data.size()) break;
        const uint32_t p_type = ReadBe32(&data[off]);
        if (p_type != 1u) continue;  // PT_LOAD
        const uint32_t p_offset = ReadBe32(&data[off + 4]);
        const uint32_t p_vaddr = ReadBe32(&data[off + 8]);
        const uint32_t p_filesz = ReadBe32(&data[off + 16]);
        if (p_offset + p_filesz <= data.size() && p_filesz > 0) {
            mem.WriteLs(p_vaddr, p_filesz, data.data() + p_offset);
        }
    }

    last_entry_pc = e_entry & mem.Lslr() & ~3u;
    if (entry_out) *entry_out = last_entry_pc;
    cpu.Reset(last_entry_pc);
    return true;
}

bool SpuMachine::LoadBinaryFile(const std::string &path, uint32_t load_addr, std::string *err_out) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        if (err_out) *err_out = "Cannot open binary file: " + path;
        return false;
    }
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)),
                              std::istreambuf_iterator<char>());
    if (data.empty()) {
        if (err_out) *err_out = "Binary file is empty";
        return false;
    }
    mem.WriteLs(load_addr, data.size(), data.data());
    last_entry_pc = load_addr & mem.Lslr() & ~3u;
    cpu.Reset(last_entry_pc);
    return true;
}

StopInfo SpuMachine::Step(bool ignore_bpt) {
    return cpu.Step(ignore_bpt);
}

StopInfo SpuMachine::RunSteps(uint64_t max_steps, bool ignore_first_bpt,
                              const std::atomic<bool> *pause_flag) {
    StopInfo last{};
    for (uint64_t i = 0; i < max_steps; ++i) {
        if (pause_flag && pause_flag->load()) {
            return StopInfo{StopReason::None, cpu.GetPC(), 0, false, "Paused"};
        }
        last = cpu.Step(i == 0 && ignore_first_bpt);
        if (last.reason != StopReason::None) {
            return last;
        }
    }
    return last;
}

bool SpuMachine::ExecuteCommand(const std::string &cmdline, std::string &output) {
    std::ostringstream oss;
    const auto args = SplitArgs(cmdline);
    if (args.empty()) {
        output.clear();
        return true;
    }

    std::string cmd = args[0];
    for (char &c : cmd) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (cmd == "help" || cmd == "?") {
        oss << "spuemu commands:\n"
            << "  status                                  - CPU, PC, SP, LR, IE, MFC, event & channel summary\n"
            << "  regs [start [count]]                    - Show GPR preferred slots (default r0..r31)\n"
            << "  vec <rN> [w0 w1 w2 w3]                  - Inspect or write 128-bit vector register\n"
            << "  disasm [addr [count]]                   - Disassemble Local Store instructions\n"
            << "  step [N]                                - Step 1 or N instructions\n"
            << "  reset [entry_pc]                        - Reset CPU & channel states\n"
            << "  ch list                                 - List all attached channel devices\n"
            << "  ch info <ch>                            - Show details & break flags for channel\n"
            << "  ch log [N]                              - Show last N channel transactions\n"
            << "  ch push <ch> <val> [val2 ...]           - Push 32-bit word(s) into channel RX queue\n"
            << "  ch pop <ch>                             - Pop 32-bit word from channel TX queue\n"
            << "  ch set <ch> <val>                       - Set register/stub channel value\n"
            << "  ch count <ch> <N>                       - Override channel rchcnt value\n"
            << "  ch break <ch> rd|wr|both|none           - Break debugger on channel read/write\n"
            << "  ch prompt <ch> on|off                   - Prompt interactively on empty rdch\n"
            << "  ch attach <ch> fifo|register|stub|responder [opts...]\n"
            << "  ch detach <ch>                          - Detach custom device (revert to stub)\n"
            << "  dev load <file.json>                    - Load channel devices & DMA regions from JSON\n"
            << "  dev save <file.json>                    - Export current channel device config to JSON\n"
            << "  dev reset                               - Restore default CBEA/PS3 channel devices\n"
            << "  mfc                                     - Show MFC registers and recent DMA transfers\n"
            << "  mbox [in <val> | out]                   - Inspect/push/pop SPU mailboxes\n"
            << "  dma list | map <ea> <size> [name] | read <ea> <len>\n"
            << "  irq [mask|raise <bits>|ack <bits>|ie 0|1]\n"
            << "  dec [val]                               - Read or set SPU Decrementer\n"
            << "  fpscr                                   - Show 128-bit FPSCR\n";
        output = oss.str();
        return true;
    }

    if (cmd == "status") {
        const uint32_t pc = cpu.GetPC();
        const uint32_t w = mem.FetchInsn(pc);
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "PC=0x%05X (%s)\nSP=0x%05X  LR=0x%05X  SRR0=0x%05X  LSLR=0x%05X  IE=%u\n"
                      "Cycles=%llu  Insns=%llu  Events=0x%08X (Mask=0x%08X)  Dec=0x%08X\n",
                      pc, DisassembleSpu(pc, w, mem.Lslr()).c_str(),
                      cpu.RegWord(1), cpu.RegWord(0),
                      channels.Events().Srr0(), mem.Lslr(),
                      channels.Events().InterruptEnabled() ? 1u : 0u,
                      static_cast<unsigned long long>(cpu.TotalCycles()),
                      static_cast<unsigned long long>(cpu.InsnCount()),
                      channels.Events().PendingEvents(), channels.Events().EventMask(),
                      channels.Events().Decrementer());
        oss << buf;
        oss << "MFC: " << channels.Mfc().Describe(CH_MFC_Cmd) << "\n";
        oss << "Mbox: " << channels.Mailbox().Describe(CH_SPU_RdInMbox) << "\n";
        output = oss.str();
        return true;
    }

    if (cmd == "regs") {
        uint32_t start = 0, count = 32;
        if (args.size() >= 2) ParseU32(args[1], &start);
        if (args.size() >= 3) ParseU32(args[2], &count);
        if (start >= 128) start = 0;
        if (start + count > 128) count = 128 - start;
        for (uint32_t r = start; r < start + count; ++r) {
            char buf[96];
            const char *alias = (r == 0) ? "lr" : (r == 1) ? "sp" : "";
            std::snprintf(buf, sizeof(buf), "r%-3u %-2s = %s\n",
                          r, alias, FormatQuadword(cpu.Reg(static_cast<uint8_t>(r))).c_str());
            oss << buf;
        }
        output = oss.str();
        return true;
    }

    if (cmd == "vec") {
        if (args.size() < 2) {
            output = "Usage: vec <rN> [w0 w1 w2 w3]";
            return false;
        }
        uint8_t r = 0;
        if (!ParseRegId(args[1], &r)) {
            output = "Invalid register: " + args[1];
            return false;
        }
        if (args.size() >= 6) {
            uint32_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
            if (!ParseU32(args[2], &w0) || !ParseU32(args[3], &w1) ||
                !ParseU32(args[4], &w2) || !ParseU32(args[5], &w3)) {
                output = "Invalid word values";
                return false;
            }
            cpu.Reg(r) = Quadword::FromWords(w0, w1, w2, w3);
        } else if (args.size() == 3) {
            uint32_t w0 = 0;
            if (!ParseU32(args[2], &w0)) { output = "Invalid word"; return false; }
            cpu.SetRegWord(r, w0);
        }
        char buf[96];
        std::snprintf(buf, sizeof(buf), "r%u = %s", r, FormatQuadword(cpu.Reg(r)).c_str());
        output = buf;
        return true;
    }

    if (cmd == "disasm" || cmd == "u") {
        uint32_t addr = cpu.GetPC();
        uint32_t cnt = 10;
        if (args.size() >= 2) ParseU32(args[1], &addr);
        if (args.size() >= 3) ParseU32(args[2], &cnt);
        addr &= mem.Lslr() & ~3u;
        for (uint32_t i = 0; i < cnt; ++i) {
            const uint32_t ea = (addr + i * 4u) & mem.Lslr();
            const uint32_t w = mem.FetchInsn(ea);
            char buf[128];
            std::snprintf(buf, sizeof(buf), "%s0x%05X: %08X  %s\n",
                          (ea == cpu.GetPC() ? "=> " : "   "),
                          ea, w, DisassembleSpu(ea, w, mem.Lslr()).c_str());
            oss << buf;
        }
        output = oss.str();
        return true;
    }

    if (cmd == "step" || cmd == "s") {
        uint32_t n = 1;
        if (args.size() >= 2) ParseU32(args[1], &n);
        if (n == 0) n = 1;
        const StopInfo st = (n == 1) ? Step(true) : RunSteps(n, true);
        char buf[160];
        std::snprintf(buf, sizeof(buf), "PC=0x%05X  reason=%u (%s)",
                      cpu.GetPC(), static_cast<unsigned>(st.reason), st.message.c_str());
        output = buf;
        return true;
    }

    if (cmd == "reset") {
        int32_t ep = -1;
        if (args.size() >= 2) {
            uint32_t v = 0;
            if (ParseU32(args[1], &v)) ep = static_cast<int32_t>(v);
        }
        Reset(ep);
        char buf[64];
        std::snprintf(buf, sizeof(buf), "Reset complete. PC=0x%05X", cpu.GetPC());
        output = buf;
        return true;
    }

    if (cmd == "ch") {
        if (args.size() < 2) {
            output = channels.FormatSummary();
            return true;
        }
        std::string sub = args[1];
        for (char &c : sub) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (sub == "list") {
            output = channels.FormatSummary();
            return true;
        }
        if (sub == "log") {
            uint32_t n = 20;
            if (args.size() >= 3) ParseU32(args[2], &n);
            const auto &lg = channels.Log();
            const size_t start = (lg.size() > n) ? (lg.size() - n) : 0;
            for (size_t i = start; i < lg.size(); ++i) {
                const auto &e = lg[i];
                const char *sym = ChannelSymbolicName(e.ch);
                char buf[192];
                std::snprintf(buf, sizeof(buf), "[cyc %llu pc=0x%05X] %c ch%u(%s) val=0x%08X %s\n",
                              static_cast<unsigned long long>(e.cycle), e.pc, e.op, e.ch,
                              sym ? sym : "-", e.value, e.note.c_str());
                oss << buf;
            }
            output = oss.str().empty() ? "(no channel transactions yet)" : oss.str();
            return true;
        }

        if (args.size() < 3) {
            output = "Missing channel argument";
            return false;
        }
        uint8_t ch = 0;
        if (!ParseChannelId(args[2], &ch)) {
            output = "Unknown channel: " + args[2];
            return false;
        }

        if (sub == "info") {
            const auto dev = channels.GetDevice(ch);
            const auto fl = channels.GetBreakFlags(ch);
            const char *sym = ChannelSymbolicName(ch);
            char buf[256];
            std::snprintf(buf, sizeof(buf), "ch%u (%s): %s | brk_rd=%d brk_wr=%d prompt=%d",
                          ch, sym ? sym : "-", dev->Describe(ch).c_str(),
                          fl.break_on_read ? 1 : 0, fl.break_on_write ? 1 : 0,
                          fl.prompt_on_empty ? 1 : 0);
            output = buf;
            return true;
        }
        if (sub == "push") {
            if (args.size() < 4) { output = "Usage: ch push <ch> <val> [val2 ...]"; return false; }
            size_t pushed = 0;
            for (size_t i = 3; i < args.size(); ++i) {
                uint32_t v = 0;
                if (!ParseU32(args[i], &v)) { output = "Invalid value: " + args[i]; return false; }
                if (!channels.PushInput(ch, v)) {
                    output = "Channel device does not support push (attach a fifo/responder first)";
                    return false;
                }
                ++pushed;
            }
            char buf[96];
            std::snprintf(buf, sizeof(buf), "Pushed %zu word(s) to ch%u", pushed, ch);
            output = buf;
            return true;
        }
        if (sub == "pop") {
            uint32_t v = 0;
            if (!channels.PopOutput(ch, &v)) {
                output = "Channel TX queue empty or device does not support pop";
                return false;
            }
            char buf[64];
            std::snprintf(buf, sizeof(buf), "0x%08X", v);
            output = buf;
            return true;
        }
        if (sub == "set") {
            if (args.size() < 4) { output = "Usage: ch set <ch> <val>"; return false; }
            uint32_t v = 0;
            if (!ParseU32(args[3], &v)) { output = "Invalid value"; return false; }
            if (!channels.SetValue(ch, v)) {
                output = "Channel device does not support set";
                return false;
            }
            char buf[64];
            std::snprintf(buf, sizeof(buf), "ch%u = 0x%08X", ch, v);
            output = buf;
            return true;
        }
        if (sub == "count") {
            if (args.size() < 4) { output = "Usage: ch count <ch> <N>"; return false; }
            uint32_t c = 0;
            if (!ParseU32(args[3], &c)) { output = "Invalid count"; return false; }
            if (!channels.SetCount(ch, c)) {
                output = "Channel device does not support count override";
                return false;
            }
            char buf[64];
            std::snprintf(buf, sizeof(buf), "ch%u count = %u", ch, c);
            output = buf;
            return true;
        }
        if (sub == "break") {
            if (args.size() < 4) { output = "Usage: ch break <ch> rd|wr|both|none"; return false; }
            std::string m = args[3];
            for (char &c : m) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (m == "rd" || m == "read") {
                channels.SetBreakOnRead(ch, true);
                channels.SetBreakOnWrite(ch, false);
            } else if (m == "wr" || m == "write") {
                channels.SetBreakOnRead(ch, false);
                channels.SetBreakOnWrite(ch, true);
            } else if (m == "both" || m == "rw") {
                channels.SetBreakOnRead(ch, true);
                channels.SetBreakOnWrite(ch, true);
            } else if (m == "none" || m == "off") {
                channels.SetBreakOnRead(ch, false);
                channels.SetBreakOnWrite(ch, false);
            } else {
                output = "Expected rd|wr|both|none";
                return false;
            }
            output = "Updated break flags for ch" + std::to_string(ch);
            return true;
        }
        if (sub == "prompt") {
            if (args.size() < 4) { output = "Usage: ch prompt <ch> on|off"; return false; }
            const bool on = (args[3] == "on" || args[3] == "1" || args[3] == "true");
            channels.SetPromptOnEmpty(ch, on);
            output = std::string("Prompt on empty for ch") + std::to_string(ch) + (on ? " ON" : " OFF");
            return true;
        }
        if (sub == "attach") {
            if (args.size() < 4) { output = "Usage: ch attach <ch> fifo|register|stub|responder [arg]"; return false; }
            std::string kind = args[3];
            for (char &c : kind) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (kind == "fifo") {
                EmptyPolicy ep = EmptyPolicy::Break;
                if (args.size() >= 5) {
                    if (args[4] == "zero") ep = EmptyPolicy::Zero;
                    else if (args[4] == "repeat") ep = EmptyPolicy::RepeatLast;
                    else if (args[4] == "stall") ep = EmptyPolicy::Stall;
                    else if (args[4] == "prompt") ep = EmptyPolicy::Prompt;
                }
                channels.AttachDevice(ch, std::make_shared<FifoChannelDevice>("cli_fifo", ep));
            } else if (kind == "register") {
                uint32_t initv = 0;
                if (args.size() >= 5) ParseU32(args[4], &initv);
                channels.AttachDevice(ch, std::make_shared<RegisterChannelDevice>("cli_reg", initv));
            } else if (kind == "stub") {
                uint32_t defv = 0;
                if (args.size() >= 5) ParseU32(args[4], &defv);
                channels.AttachDevice(ch, std::make_shared<StubLoggerDevice>("cli_stub", defv, 1));
            } else if (kind == "responder") {
                auto resp = std::make_shared<ResponderChannelDevice>("cli_resp");
                // Optional inline rule: when=reply (e.g. 0x1=0xAABBCCDD)
                for (size_t i = 4; i < args.size(); ++i) {
                    const size_t eq = args[i].find('=');
                    if (eq != std::string::npos) {
                        ResponderRule r;
                        const std::string lhs = args[i].substr(0, eq);
                        const std::string rhs = args[i].substr(eq + 1);
                        if (lhs == "*") r.match_any = true;
                        else ParseU32(lhs, &r.when_write);
                        uint32_t rv = 0;
                        if (ParseU32(rhs, &rv)) r.reply_words.push_back(rv);
                        resp->AddRule(r);
                    }
                }
                channels.AttachDevice(ch, resp);
            } else {
                output = "Unknown device kind: " + kind;
                return false;
            }
            output = "Attached " + kind + " to ch" + std::to_string(ch);
            return true;
        }
        if (sub == "detach") {
            channels.DetachDevice(ch);
            output = "Detached custom device from ch" + std::to_string(ch);
            return true;
        }
        output = "Unknown ch subcommand: " + sub;
        return false;
    }

    if (cmd == "dev") {
        if (args.size() < 2) { output = "Usage: dev load <path> | save <path> | reset"; return false; }
        std::string sub = args[1];
        for (char &c : sub) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (sub == "load" && args.size() >= 3) {
            std::string err;
            if (!channels.LoadConfigFile(args[2], &err)) {
                output = "ERROR: " + err;
                return false;
            }
            output = "Loaded channel device config: " + args[2];
            return true;
        }
        if (sub == "save" && args.size() >= 3) {
            std::string err;
            if (!channels.SaveConfigFile(args[2], &err)) {
                output = "ERROR: " + err;
                return false;
            }
            output = "Saved channel device config: " + args[2];
            return true;
        }
        if (sub == "reset") {
            channels.ResetToDefaults();
            output = "Restored default CBEA/PS3 channel devices";
            return true;
        }
        output = "Usage: dev load <path> | save <path> | reset";
        return false;
    }

    if (cmd == "mfc") {
        oss << channels.Mfc().Describe(CH_MFC_Cmd) << "\n";
        const auto &h = channels.Mfc().History();
        for (const auto &r : h) {
            char buf[160];
            std::snprintf(buf, sizeof(buf), "  cmd=0x%02X LSA=0x%05X EA=0x%016llX size=0x%X tag=%u %s\n",
                          r.cmd, r.lsa, static_cast<unsigned long long>(r.ea), r.size, r.tag,
                          r.ok ? "OK" : "ERR");
            oss << buf;
        }
        output = oss.str();
        return true;
    }

    if (cmd == "mbox") {
        if (args.size() >= 3 && args[1] == "in") {
            uint32_t v = 0;
            if (!ParseU32(args[2], &v)) { output = "Invalid value"; return false; }
            channels.PushInput(CH_SPU_RdInMbox, v);
            char buf[64];
            std::snprintf(buf, sizeof(buf), "Pushed 0x%08X to SPU_RdInMbox", v);
            output = buf;
            return true;
        }
        if (args.size() >= 2 && args[1] == "out") {
            uint32_t v = 0;
            if (!channels.PopOutput(CH_SPU_WrOutMbox, &v)) {
                output = "SPU_WrOutMbox empty";
                return false;
            }
            char buf[64];
            std::snprintf(buf, sizeof(buf), "0x%08X", v);
            output = buf;
            return true;
        }
        output = channels.Mailbox().Describe(CH_SPU_RdInMbox);
        return true;
    }

    if (cmd == "dma") {
        if (args.size() < 2 || args[1] == "list") {
            const auto &regs = mem.MainRegions();
            if (regs.empty()) { output = "(no mapped EA DMA regions; auto_map_ea=" + std::string(mem.AutoMapEa() ? "on" : "off") + ")"; return true; }
            for (const auto &r : regs) {
                char buf[128];
                std::snprintf(buf, sizeof(buf), "  0x%016llX .. 0x%016llX (%zu bytes) %s%s\n",
                              static_cast<unsigned long long>(r.base),
                              static_cast<unsigned long long>(r.base + r.data.size()),
                              r.data.size(), r.name.c_str(), r.read_only ? " [RO]" : "");
                oss << buf;
            }
            output = oss.str();
            return true;
        }
        if (args[1] == "map" && args.size() >= 4) {
            uint64_t ea = 0, sz = 0;
            if (!ParseU64(args[2], &ea) || !ParseU64(args[3], &sz)) { output = "Invalid ea/size"; return false; }
            const std::string name = args.size() >= 5 ? args[4] : "ea_ram";
            mem.MapMainMemory(ea, static_cast<size_t>(sz), name, false);
            output = "Mapped EA region " + name;
            return true;
        }
        if (args[1] == "read" && args.size() >= 4) {
            uint64_t ea = 0;
            uint32_t len = 0;
            if (!ParseU64(args[2], &ea) || !ParseU32(args[3], &len)) { output = "Invalid ea/len"; return false; }
            len = std::min<uint32_t>(len, 256u);
            std::vector<uint8_t> buf(len);
            if (!mem.ReadMainMemory(ea, len, buf.data())) { output = "EA unmapped"; return false; }
            for (size_t i = 0; i < buf.size(); ++i) {
                char hb[8];
                std::snprintf(hb, sizeof(hb), "%02X%s", buf[i], ((i + 1) % 16 == 0) ? "\n" : " ");
                oss << hb;
            }
            output = oss.str();
            return true;
        }
        output = "Usage: dma list | map <ea> <size> [name] | read <ea> <len>";
        return false;
    }

    if (cmd == "irq") {
        if (args.size() >= 3 && args[1] == "raise") {
            uint32_t bits = 0;
            if (!ParseU32(args[2], &bits)) { output = "Invalid mask"; return false; }
            channels.Events().RaiseEvent(bits);
        } else if (args.size() >= 3 && args[1] == "ack") {
            uint32_t bits = 0;
            if (!ParseU32(args[2], &bits)) { output = "Invalid mask"; return false; }
            channels.Events().ClearEvent(bits);
        } else if (args.size() >= 3 && args[1] == "mask") {
            uint32_t bits = 0;
            if (!ParseU32(args[2], &bits)) { output = "Invalid mask"; return false; }
            channels.Events().SetValue(CH_SPU_WrEventMask, bits);
        } else if (args.size() >= 3 && args[1] == "ie") {
            channels.Events().SetInterruptEnable(args[2] == "1" || args[2] == "on");
        }
        char buf[128];
        std::snprintf(buf, sizeof(buf), "Events=0x%08X Mask=0x%08X IE=%u SRR0=0x%05X",
                      channels.Events().PendingEvents(), channels.Events().EventMask(),
                      channels.Events().InterruptEnabled() ? 1u : 0u, channels.Events().Srr0());
        output = buf;
        return true;
    }

    if (cmd == "dec") {
        if (args.size() >= 2) {
            uint32_t v = 0;
            if (!ParseU32(args[1], &v)) { output = "Invalid value"; return false; }
            channels.Events().SetDecrementer(v);
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf), "Decrementer=0x%08X", channels.Events().Decrementer());
        output = buf;
        return true;
    }

    if (cmd == "fpscr") {
        output = "FPSCR = " + FormatQuadword(cpu.Fpscr());
        return true;
    }

    output = "Unknown command: " + args[0] + " (type 'help')";
    return false;
}

}  // namespace spu
