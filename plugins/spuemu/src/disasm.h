#pragma once

#include <cstdint>
#include <string>

namespace spu {

// Disassemble a single 32-bit big-endian SPU instruction at `pc` (using `lslr` mask).
std::string DisassembleSpu(uint32_t pc, uint32_t word, uint32_t lslr = 0x3FFFFu);

}  // namespace spu
