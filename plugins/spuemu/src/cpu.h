#pragma once

#include "memory.h"
#include "spu_channels.h"

#include <array>
#include <cstdint>
#include <string>
#include <unordered_set>

namespace spu {

enum class RunState : uint8_t {
    Running = 0,
    Stopped,        // stop / stopd
    Halted,         // heq / hgt / hlgt
    ChannelStalled, // waiting on empty/full channel
};

enum class StopReason : uint8_t {
    None = 0,
    Breakpoint,
    Watchpoint,
    StopInsn,       // stop #signal
    StopdInsn,      // stopd
    HaltInsn,       // heq/hgt/hlgt triggered
    ChannelBreak,   // break_on_read / break_on_write / empty-channel break
    ChannelStall,   // stalled on empty channel
    InvalidInsn,    // illegal/reserved opcode
};

struct StopInfo {
    StopReason reason = StopReason::None;
    uint32_t pc = 0;
    uint32_t detail = 0;  // stop signal / channel ID / watchpoint addr / opcode
    bool is_write = false;
    std::string message;
};

class SpuCpu {
public:
    SpuCpu(SpuMemory *mem, ChannelRouter *channels);

    void Reset(uint32_t entry_pc = 0);

    // Execute a single instruction
    StopInfo Step(bool ignore_bpt = false);

    // Register accessors
    uint32_t GetPC() const { return pc_; }
    void SetPC(uint32_t pc) { pc_ = (pc & mem_->Lslr()) & ~3u; }

    const Quadword &Reg(uint8_t r) const { return gpr_[r & 0x7Fu]; }
    Quadword &Reg(uint8_t r) { return gpr_[r & 0x7Fu]; }
    uint32_t RegWord(uint8_t r) const { return gpr_[r & 0x7Fu].PrefU32(); }
    void SetRegWord(uint8_t r, uint32_t w) { gpr_[r & 0x7Fu].SetPrefU32(w); }

    const Quadword &Fpscr() const { return fpscr_; }
    void SetFpscr(const Quadword &q) { fpscr_ = q; }

    const Quadword &Spr(uint8_t s) const { return spr_[s & 0x7Fu]; }
    void SetSpr(uint8_t s, const Quadword &q) { spr_[s & 0x7Fu] = q; }

    RunState GetRunState() const { return run_state_; }
    void SetRunState(RunState st) { run_state_ = st; }

    bool ExternalDataPending() const { return ext_data_pending_; }
    void SetExternalDataPending(bool p) { ext_data_pending_ = p; }

    uint64_t TotalCycles() const { return total_cycles_; }
    uint64_t InsnCount() const { return insn_count_; }

    // Virtual non-intrusive breakpoints
    void AddBreakpoint(uint32_t addr) { bpts_.insert(addr & SpuMemory::kDefaultLslr & ~3u); }
    void RemoveBreakpoint(uint32_t addr) { bpts_.erase(addr & SpuMemory::kDefaultLslr & ~3u); }
    void ClearBreakpoints() { bpts_.clear(); }
    bool HasBreakpoint(uint32_t addr) const {
        return bpts_.find(addr & SpuMemory::kDefaultLslr & ~3u) != bpts_.end();
    }
    const std::unordered_set<uint32_t> &Breakpoints() const { return bpts_; }

private:
    StopInfo ExecuteInstruction(uint32_t insn_pc, uint32_t word);
    void ApplyBranchDE(uint32_t word);
    void DeliverPendingInterrupt();

    // Extended-range SPU single-precision helpers (CBEA SPU ISA §10)
    static float BitsToF32(uint32_t u);
    static uint32_t F32ToBits(float f);
    static double BitsToF64(uint64_t u);
    static uint64_t F64ToBits(double d);
    static float FlushDenormF32(uint32_t bits);
    static uint32_t PackSpuF32(float v);

    SpuMemory *mem_ = nullptr;
    ChannelRouter *channels_ = nullptr;

    std::array<Quadword, 128> gpr_{};
    std::array<Quadword, 128> spr_{};
    Quadword fpscr_{};
    uint32_t pc_ = 0;
    RunState run_state_ = RunState::Running;
    bool ext_data_pending_ = false;
    uint64_t total_cycles_ = 0;
    uint64_t insn_count_ = 0;
    std::unordered_set<uint32_t> bpts_;
};

}  // namespace spu
