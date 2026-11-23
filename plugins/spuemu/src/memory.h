#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace spu {

// 128-bit big-endian SPU quadword (byte 0 = most significant byte, word 0 = preferred slot)
struct Quadword {
    std::array<uint8_t, 16> b{};

    void Clear() { b.fill(0); }

    uint8_t U8(size_t idx) const { return b[idx & 15u]; }
    int8_t  S8(size_t idx) const { return static_cast<int8_t>(b[idx & 15u]); }
    void SetU8(size_t idx, uint8_t v) { b[idx & 15u] = v; }

    uint16_t U16(size_t idx) const {
        const size_t o = (idx & 7u) * 2u;
        return static_cast<uint16_t>((static_cast<uint16_t>(b[o]) << 8) | b[o + 1u]);
    }
    int16_t S16(size_t idx) const { return static_cast<int16_t>(U16(idx)); }
    void SetU16(size_t idx, uint16_t v) {
        const size_t o = (idx & 7u) * 2u;
        b[o] = static_cast<uint8_t>((v >> 8) & 0xFFu);
        b[o + 1u] = static_cast<uint8_t>(v & 0xFFu);
    }

    uint32_t U32(size_t idx) const {
        const size_t o = (idx & 3u) * 4u;
        return (static_cast<uint32_t>(b[o]) << 24) |
               (static_cast<uint32_t>(b[o + 1u]) << 16) |
               (static_cast<uint32_t>(b[o + 2u]) << 8) |
               static_cast<uint32_t>(b[o + 3u]);
    }
    int32_t S32(size_t idx) const { return static_cast<int32_t>(U32(idx)); }
    void SetU32(size_t idx, uint32_t v) {
        const size_t o = (idx & 3u) * 4u;
        b[o] = static_cast<uint8_t>((v >> 24) & 0xFFu);
        b[o + 1u] = static_cast<uint8_t>((v >> 16) & 0xFFu);
        b[o + 2u] = static_cast<uint8_t>((v >> 8) & 0xFFu);
        b[o + 3u] = static_cast<uint8_t>(v & 0xFFu);
    }

    uint64_t U64(size_t idx) const {
        const size_t w = (idx & 1u) * 2u;
        return (static_cast<uint64_t>(U32(w)) << 32) | U32(w + 1u);
    }
    int64_t S64(size_t idx) const { return static_cast<int64_t>(U64(idx)); }
    void SetU64(size_t idx, uint64_t v) {
        const size_t w = (idx & 1u) * 2u;
        SetU32(w, static_cast<uint32_t>(v >> 32));
        SetU32(w + 1u, static_cast<uint32_t>(v & 0xFFFFFFFFu));
    }

    // Preferred slot (word 0, bytes 0..3)
    uint32_t PrefU32() const { return U32(0); }
    int32_t  PrefS32() const { return S32(0); }
    void SetPrefU32(uint32_t v) { SetU32(0, v); }

    static Quadword FromWords(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3) {
        Quadword q;
        q.SetU32(0, w0);
        q.SetU32(1, w1);
        q.SetU32(2, w2);
        q.SetU32(3, w3);
        return q;
    }

    static Quadword SplatU32(uint32_t w) { return FromWords(w, w, w, w); }
    static Quadword SplatU16(uint16_t h) {
        const uint32_t w = (static_cast<uint32_t>(h) << 16) | h;
        return SplatU32(w);
    }
    static Quadword SplatU8(uint8_t byte) {
        Quadword q;
        q.b.fill(byte);
        return q;
    }

    bool operator==(const Quadword &o) const { return b == o.b; }
    bool operator!=(const Quadword &o) const { return b != o.b; }
};

struct Watchpoint {
    uint32_t addr = 0;
    uint32_t size = 1;
    int type = 0;  // 1=write, 2=read, 3=rdwr
};

struct WatchHit {
    bool hit = false;
    uint32_t addr = 0;
    bool is_write = false;
};

struct MainMemRegion {
    uint64_t base = 0;
    std::string name;
    std::vector<uint8_t> data;
    bool read_only = false;
};

class SpuMemory {
public:
    static constexpr uint32_t kLocalStoreSize = 0x40000u;  // 256 KiB
    static constexpr uint32_t kDefaultLslr    = 0x3FFFFu;  // Local Store Limit Register

    SpuMemory();

    void Reset();
    void ClearLocalStore();
    void ClearMainMemory();

    uint32_t Lslr() const { return lslr_; }
    void SetLslr(uint32_t mask) { lslr_ = mask & kDefaultLslr; }
    uint32_t WrapLs(uint32_t addr) const { return addr & lslr_; }

    // Instruction fetch (word-aligned, big-endian)
    uint32_t FetchInsn(uint32_t pc) const;

    // Architectural quadword load/store (masks low 4 bits, wraps by LSLR, checks watchpoints)
    Quadword LoadQuadword(uint32_t addr);
    void StoreQuadword(uint32_t addr, const Quadword &q);

    // Raw Local Store debug/DMA access (does not trigger CPU watchpoints)
    bool ReadLs(uint32_t addr, size_t len, void *out) const;
    bool WriteLs(uint32_t addr, size_t len, const void *data);
    uint8_t PeekLsByte(uint32_t addr) const { return ls_[addr & kDefaultLslr]; }
    void PokeLsByte(uint32_t addr, uint8_t val) { ls_[addr & kDefaultLslr] = val; }
    const uint8_t *LocalStoreData() const { return ls_.data(); }
    uint8_t *LocalStoreData() { return ls_.data(); }

    // 64-bit Main Memory (EA) space for MFC DMA
    bool MapMainMemory(uint64_t ea, size_t size, const std::string &name = "ea_ram",
                       bool read_only = false);
    bool MapMainMemoryData(uint64_t ea, const uint8_t *data, size_t size,
                           const std::string &name = "ea_ram", bool read_only = false);
    bool UnmapMainMemory(uint64_t ea);
    bool ReadMainMemory(uint64_t ea, size_t len, void *out) const;
    bool WriteMainMemory(uint64_t ea, size_t len, const void *data);
    const std::vector<MainMemRegion> &MainRegions() const { return ea_regions_; }

    // Auto-map unmapped EA pages on DMA write/read (default: true for ergonomic firmware testing)
    void SetAutoMapEa(bool enable) { auto_map_ea_ = enable; }
    bool AutoMapEa() const { return auto_map_ea_; }

    // Local Store watchpoints
    void AddWatchpoint(uint32_t addr, uint32_t size, int type);
    void RemoveWatchpoint(uint32_t addr, uint32_t size, int type);
    void ClearWatchpoints();
    const std::vector<Watchpoint> &Watchpoints() const { return watchpoints_; }
    WatchHit ConsumeWatchHit();

    // Atomic reservation (MFC GETLLAR / PUTLLC)
    bool HasReservation() const { return reservation_valid_; }
    uint64_t ReservationEa() const { return reservation_ea_; }
    void SetReservation(uint64_t ea) { reservation_valid_ = true; reservation_ea_ = ea & ~uint64_t(0x7F); }
    void ClearReservation() { reservation_valid_ = false; }

private:
    void CheckWatch(uint32_t addr, uint32_t size, bool is_write);
    MainMemRegion *FindEaRegionMut(uint64_t ea, size_t len);
    const MainMemRegion *FindEaRegion(uint64_t ea, size_t len) const;

    std::array<uint8_t, kLocalStoreSize> ls_{};
    uint32_t lslr_ = kDefaultLslr;
    std::vector<MainMemRegion> ea_regions_;
    bool auto_map_ea_ = true;

    std::vector<Watchpoint> watchpoints_;
    WatchHit pending_watch_{};

    bool reservation_valid_ = false;
    uint64_t reservation_ea_ = 0;
};

}  // namespace spu
