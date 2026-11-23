#pragma once

#include "cpu.h"
#include "memory.h"
#include "spu_channels.h"

#include <atomic>
#include <cstdint>
#include <string>

namespace spu {

class SpuMachine {
public:
    SpuMachine();

    void Reset(int32_t entry_pc_override = -1);

    // Load a 32-bit big-endian SPU ELF (EM_SPU = 23) or raw binary into Local Store
    bool LoadElfFile(const std::string &path, uint32_t *entry_out = nullptr, std::string *err_out = nullptr);
    bool LoadBinaryFile(const std::string &path, uint32_t load_addr = 0, std::string *err_out = nullptr);

    StopInfo Step(bool ignore_bpt = false);
    StopInfo RunSteps(uint64_t max_steps, bool ignore_first_bpt = false,
                      const std::atomic<bool> *pause_flag = nullptr);

    // Interactive command interpreter (shared by spuemu CLI, GDB monitor, and IDA spuemu> console)
    bool ExecuteCommand(const std::string &cmdline, std::string &output);

    SpuMemory mem;
    ChannelRouter channels;
    SpuCpu cpu;
    uint32_t last_entry_pc = 0;
};

}  // namespace spu
