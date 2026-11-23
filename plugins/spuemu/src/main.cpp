#include "debugger.h"
#include "machine.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

void PrintUsage(const char *argv0) {
    std::printf(
        "Cell Broadband Engine SPU Emulator (spuemu)\n"
        "Usage: %s [options]\n"
        "  --elf <path>         Load 32-bit big-endian SPU ELF into Local Store\n"
        "  --bin <path>         Load raw binary into Local Store\n"
        "  --load <addr>        Load address for --bin (default 0x0)\n"
        "  --entry <addr>       Override entry PC\n"
        "  --channels <json>    Load pluggable channel devices & DMA regions JSON\n"
        "  --cmd <command>      Execute interactive command (repeatable)\n"
        "  --steps <N>          Execute N steps and print status\n"
        "  --gdb [port]         Start GDB RSP server (default port 23946)\n"
        "  --repl               Start interactive spuemu> shell\n",
        argv0);
}

}  // namespace

int main(int argc, char **argv) {
    spu::SpuMachine machine;

    std::string elf_path;
    std::string bin_path;
    std::string ch_json;
    uint32_t load_addr = 0;
    bool has_entry = false;
    uint32_t entry_pc = 0;
    uint64_t steps = 0;
    bool run_gdb = false;
    int gdb_port = 23946;
    bool run_repl = false;
    std::vector<std::string> cmds;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        } else if (arg == "--elf" && i + 1 < argc) {
            elf_path = argv[++i];
        } else if (arg == "--bin" && i + 1 < argc) {
            bin_path = argv[++i];
        } else if (arg == "--load" && i + 1 < argc) {
            load_addr = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        } else if (arg == "--entry" && i + 1 < argc) {
            entry_pc = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
            has_entry = true;
        } else if (arg == "--channels" && i + 1 < argc) {
            ch_json = argv[++i];
        } else if (arg == "--cmd" && i + 1 < argc) {
            cmds.push_back(argv[++i]);
        } else if (arg == "--steps" && i + 1 < argc) {
            steps = std::strtoull(argv[++i], nullptr, 0);
        } else if (arg == "--gdb") {
            run_gdb = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                gdb_port = std::atoi(argv[++i]);
            }
        } else if (arg == "--repl") {
            run_repl = true;
        } else {
            std::fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
            PrintUsage(argv[0]);
            return 1;
        }
    }

    std::string err;
    if (!elf_path.empty()) {
        if (!machine.LoadElfFile(elf_path, nullptr, &err)) {
            std::fprintf(stderr, "ERROR: %s\n", err.c_str());
            return 1;
        }
    } else if (!bin_path.empty()) {
        if (!machine.LoadBinaryFile(bin_path, load_addr, &err)) {
            std::fprintf(stderr, "ERROR: %s\n", err.c_str());
            return 1;
        }
    }

    if (has_entry) {
        machine.cpu.SetPC(entry_pc);
        machine.last_entry_pc = entry_pc;
    }

    if (!ch_json.empty()) {
        if (!machine.channels.LoadConfigFile(ch_json, &err)) {
            std::fprintf(stderr, "ERROR: %s\n", err.c_str());
            return 1;
        }
    }

    for (const auto &c : cmds) {
        std::string out;
        machine.ExecuteCommand(c, out);
        if (!out.empty()) std::printf("%s\n", out.c_str());
    }

    if (steps > 0) {
        const auto stop = machine.RunSteps(steps, false);
        std::string out;
        machine.ExecuteCommand("status", out);
        std::printf("%s\nStop reason=%u (%s)\n", out.c_str(),
                    static_cast<unsigned>(stop.reason), stop.message.c_str());
    }

    if (run_gdb) {
        spu::GdbServer gdb(&machine, gdb_port);
        gdb.WaitForConnection();
    }

    if (run_repl) {
        std::string line;
        while (true) {
            std::printf("spuemu> ");
            std::fflush(stdout);
            if (!std::getline(std::cin, line)) break;
            if (line == "quit" || line == "exit" || line == "q") break;
            std::string out;
            machine.ExecuteCommand(line, out);
            if (!out.empty()) std::printf("%s\n", out.c_str());
        }
    }

    return 0;
}
