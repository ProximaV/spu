#include "memory.h"

#include <algorithm>
#include <cstring>

namespace spu {

SpuMemory::SpuMemory() {
    Reset();
}

void SpuMemory::Reset() {
    lslr_ = kDefaultLslr;
    pending_watch_ = {};
    reservation_valid_ = false;
    reservation_ea_ = 0;
}

void SpuMemory::ClearLocalStore() {
    ls_.fill(0);
}

void SpuMemory::ClearMainMemory() {
    ea_regions_.clear();
    reservation_valid_ = false;
}

uint32_t SpuMemory::FetchInsn(uint32_t pc) const {
    const uint32_t a = (pc & lslr_) & ~3u;
    return (static_cast<uint32_t>(ls_[a]) << 24) |
           (static_cast<uint32_t>(ls_[a + 1u]) << 16) |
           (static_cast<uint32_t>(ls_[a + 2u]) << 8) |
           static_cast<uint32_t>(ls_[a + 3u]);
}

Quadword SpuMemory::LoadQuadword(uint32_t addr) {
    const uint32_t aligned = (addr & lslr_) & ~15u;
    CheckWatch(aligned, 16u, false);
    Quadword q;
    std::memcpy(q.b.data(), ls_.data() + aligned, 16u);
    return q;
}

void SpuMemory::StoreQuadword(uint32_t addr, const Quadword &q) {
    const uint32_t aligned = (addr & lslr_) & ~15u;
    CheckWatch(aligned, 16u, true);
    std::memcpy(ls_.data() + aligned, q.b.data(), 16u);
}

bool SpuMemory::ReadLs(uint32_t addr, size_t len, void *out) const {
    if (!out) return false;
    uint8_t *dst = static_cast<uint8_t *>(out);
    for (size_t i = 0; i < len; ++i) {
        dst[i] = ls_[(addr + static_cast<uint32_t>(i)) & kDefaultLslr];
    }
    return true;
}

bool SpuMemory::WriteLs(uint32_t addr, size_t len, const void *data) {
    if (!data) return false;
    const uint8_t *src = static_cast<const uint8_t *>(data);
    for (size_t i = 0; i < len; ++i) {
        ls_[(addr + static_cast<uint32_t>(i)) & kDefaultLslr] = src[i];
    }
    return true;
}

bool SpuMemory::MapMainMemory(uint64_t ea, size_t size, const std::string &name, bool read_only) {
    if (size == 0) return false;
    // Replace existing region with identical base if present
    for (auto &r : ea_regions_) {
        if (r.base == ea) {
            r.name = name;
            r.data.assign(size, 0);
            r.read_only = read_only;
            return true;
        }
    }
    MainMemRegion reg;
    reg.base = ea;
    reg.name = name;
    reg.data.assign(size, 0);
    reg.read_only = read_only;
    ea_regions_.push_back(std::move(reg));
    return true;
}

bool SpuMemory::MapMainMemoryData(uint64_t ea, const uint8_t *data, size_t size,
                                  const std::string &name, bool read_only) {
    if (size == 0) return false;
    if (!MapMainMemory(ea, size, name, read_only)) return false;
    if (data) {
        MainMemRegion *r = FindEaRegionMut(ea, size);
        if (r) {
            std::memcpy(r->data.data() + (ea - r->base), data, size);
        }
    }
    return true;
}

bool SpuMemory::UnmapMainMemory(uint64_t ea) {
    auto it = std::remove_if(ea_regions_.begin(), ea_regions_.end(),
                             [ea](const MainMemRegion &r) { return r.base == ea; });
    if (it == ea_regions_.end()) return false;
    ea_regions_.erase(it, ea_regions_.end());
    return true;
}

const MainMemRegion *SpuMemory::FindEaRegion(uint64_t ea, size_t len) const {
    for (const auto &r : ea_regions_) {
        if (ea >= r.base && (ea - r.base) + len <= r.data.size()) {
            return &r;
        }
    }
    return nullptr;
}

MainMemRegion *SpuMemory::FindEaRegionMut(uint64_t ea, size_t len) {
    for (auto &r : ea_regions_) {
        if (ea >= r.base && (ea - r.base) + len <= r.data.size()) {
            return &r;
        }
    }
    return nullptr;
}

bool SpuMemory::ReadMainMemory(uint64_t ea, size_t len, void *out) const {
    if (!out) return false;
    if (len == 0) return true;
    uint8_t *dst = static_cast<uint8_t *>(out);
    if (const MainMemRegion *r = FindEaRegion(ea, len)) {
        std::memcpy(dst, r->data.data() + (ea - r->base), len);
        return true;
    }
    // Byte-wise fallback across adjacent regions or zero-fill when auto_map_ea_ is enabled
    bool any_found = false;
    for (size_t i = 0; i < len; ++i) {
        const uint64_t cur = ea + i;
        bool hit = false;
        for (const auto &r : ea_regions_) {
            if (cur >= r.base && cur < r.base + r.data.size()) {
                dst[i] = r.data[static_cast<size_t>(cur - r.base)];
                hit = true;
                any_found = true;
                break;
            }
        }
        if (!hit) {
            if (!auto_map_ea_) return false;
            dst[i] = 0;
        }
    }
    return any_found || auto_map_ea_;
}

bool SpuMemory::WriteMainMemory(uint64_t ea, size_t len, const void *data) {
    if (!data) return false;
    if (len == 0) return true;
    const uint8_t *src = static_cast<const uint8_t *>(data);
    if (MainMemRegion *r = FindEaRegionMut(ea, len)) {
        if (r->read_only) return false;
        std::memcpy(r->data.data() + (ea - r->base), src, len);
        return true;
    }
    if (!auto_map_ea_) return false;

    // Lazily allocate a 64 KiB aligned page (or larger if transfer exceeds 64 KiB)
    const uint64_t page_base = ea & ~uint64_t(0xFFFF);
    const size_t needed = static_cast<size_t>((ea - page_base) + len);
    const size_t alloc_sz = (needed + 0xFFFFu) & ~size_t(0xFFFFu);
    MapMainMemory(page_base, alloc_sz, "auto_ea", false);
    if (MainMemRegion *r = FindEaRegionMut(ea, len)) {
        std::memcpy(r->data.data() + (ea - r->base), src, len);
        return true;
    }
    return false;
}

void SpuMemory::AddWatchpoint(uint32_t addr, uint32_t size, int type) {
    if (size == 0) size = 1;
    for (const auto &w : watchpoints_) {
        if (w.addr == addr && w.size == size && w.type == type) return;
    }
    watchpoints_.push_back(Watchpoint{addr & kDefaultLslr, size, type});
}

void SpuMemory::RemoveWatchpoint(uint32_t addr, uint32_t size, int type) {
    const uint32_t a = addr & kDefaultLslr;
    watchpoints_.erase(
        std::remove_if(watchpoints_.begin(), watchpoints_.end(),
                       [a, size, type](const Watchpoint &w) {
                           return w.addr == a && (size == 0 || w.size == size) &&
                                  (type == 0 || w.type == type);
                       }),
        watchpoints_.end());
}

void SpuMemory::ClearWatchpoints() {
    watchpoints_.clear();
    pending_watch_ = {};
}

WatchHit SpuMemory::ConsumeWatchHit() {
    WatchHit out = pending_watch_;
    pending_watch_ = {};
    return out;
}

void SpuMemory::CheckWatch(uint32_t addr, uint32_t size, bool is_write) {
    if (watchpoints_.empty()) return;
    const uint32_t a0 = addr;
    const uint32_t a1 = addr + size;
    for (const auto &w : watchpoints_) {
        const bool match_type = is_write ? ((w.type & 1) != 0) : ((w.type & 2) != 0);
        if (!match_type) continue;
        const uint32_t w0 = w.addr;
        const uint32_t w1 = w.addr + w.size;
        if (a0 < w1 && w0 < a1) {
            pending_watch_ = WatchHit{true, std::max(a0, w0), is_write};
            return;
        }
    }
}

}  // namespace spu
