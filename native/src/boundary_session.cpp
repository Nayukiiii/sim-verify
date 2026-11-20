#include "sim_verify/boundary_session.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace sim_verify::native {
namespace {

std::array<uint32_t, OverlapTracker::kMaxSites>& thread_recursion_depths() noexcept {
    thread_local std::array<uint32_t, OverlapTracker::kMaxSites> depths{};
    return depths;
}

}  // namespace

bool StartGate::observe(bool active, uint64_t logical_tick) noexcept {
    if (opened) {
        return true;
    }
    if (!active) {
        have = false;
        streak = 0;
        return false;
    }
    if (!have) {
        have = true;
        last = logical_tick;
        streak = 0;
        return false;
    }
    if (logical_tick > last) {
        last = logical_tick;
        if (++streak >= 2) {
            opened = true;
            return true;
        }
        return false;
    }
    if (logical_tick < last) {
        last = logical_tick;
        streak = 0;
    }
    return false;
}

void StartGate::reset() noexcept {
    opened = false;
    have = false;
    streak = 0;
    last = 0;
}

bool OverlapTracker::mark_and_check_overlap_locked(uint32_t site, uint64_t unit, uint32_t thread) noexcept {
    if (site >= kMaxSites) {
        return false;
    }
    bool overlap = false;
    for (InFlightSlot& slot : slots_[site]) {
        if (slot.unit == unit) {
            slot.tainted = true;
            overlap = true;
        }
    }
    for (uint32_t s = 0; s < kMaxSites; ++s) {
        if (s == site) {
            continue;
        }
        for (InFlightSlot& slot : slots_[s]) {
            if (slot.unit == unit && slot.thread != thread) {
                slot.tainted = true;
                overlap = true;
            }
        }
    }
    return overlap;
}

bool OverlapTracker::mark_and_check_overlap(uint32_t site, uint64_t unit, uint32_t thread) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return mark_and_check_overlap_locked(site, unit, thread);
}

void OverlapTracker::push_slot(uint32_t site, uint64_t unit, uint32_t thread, uint32_t order, bool tainted) noexcept {
    if (site >= kMaxSites) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    slots_[site].push_back(InFlightSlot{unit, thread, order, tainted});
}

bool OverlapTracker::enter_slot(uint32_t site, uint64_t unit, uint32_t thread, uint32_t order) noexcept {
    if (site >= kMaxSites) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    const bool overlap = mark_and_check_overlap_locked(site, unit, thread);
    slots_[site].push_back(InFlightSlot{unit, thread, order, overlap});
    return overlap;
}

bool OverlapTracker::take_slot_tainted(uint32_t site, uint64_t unit, uint32_t thread, uint32_t order) noexcept {
    if (site >= kMaxSites) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto& vec = slots_[site];
    for (size_t i = 0; i < vec.size(); ++i) {
        if (vec[i].unit == unit && vec[i].thread == thread && vec[i].order == order) {
            const bool tainted = vec[i].tainted;
            vec.erase(vec.begin() + static_cast<std::ptrdiff_t>(i));
            return tainted;
        }
    }
    return false;
}

bool OverlapTracker::is_unit_in_flight(uint64_t unit, uint32_t current_thread, uint32_t primary_site) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (primary_site < kMaxSites) {
        for (const InFlightSlot& slot : slots_[primary_site]) {
            if (slot.unit == unit) {
                return true;
            }
        }
    }
    for (uint32_t s = 0; s < kMaxSites; ++s) {
        if (s == primary_site) {
            continue;
        }
        for (const InFlightSlot& slot : slots_[s]) {
            if (slot.unit == unit && slot.thread != current_thread) {
                return true;
            }
        }
    }
    return false;
}

size_t OverlapTracker::in_flight_count(uint32_t site) const noexcept {
    if (site >= kMaxSites) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return slots_[site].size();
}

void OverlapTracker::clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& vec : slots_) {
        vec.clear();
    }
}

bool OverlapTracker::enter_recursion(uint32_t site) noexcept {
    if (site >= kMaxSites) {
        return false;
    }
    auto& depths = thread_recursion_depths();
    return depths[site]++ > 0;
}

bool OverlapTracker::exit_recursion(uint32_t site) noexcept {
    if (site >= kMaxSites) {
        return false;
    }
    auto& depths = thread_recursion_depths();
    if (depths[site] > 0) {
        --depths[site];
    }
    return depths[site] > 0;
}

uint32_t OverlapTracker::recursion_depth(uint32_t site) noexcept {
    if (site >= kMaxSites) {
        return 0;
    }
    return thread_recursion_depths()[site];
}

void ReadOnlyVerifier::capture(const RuleTable& rules, const std::vector<Region>& regions, std::vector<Snapshot>& out) {
    out.clear();
    for (const Region& region : regions) {
        if (!category_check(rules, region.category)) {
            continue;
        }
        Snapshot snap;
        snap.address = region.address;
        snap.size = region.size;
        snap.category = region.category;
        snap.bytes.resize(region.size);
        if (!read_memory(region.address, snap.bytes.data(), region.size)) {
            continue;
        }
        out.push_back(std::move(snap));
    }
}

uint32_t ReadOnlyVerifier::verify(const RuleTable& rules,
                                  const std::vector<Region>& regions,
                                  const std::vector<Snapshot>& reference,
                                  uint32_t& changed_mask_out) {
    uint32_t status = 0;
    std::unordered_map<uint64_t, const Snapshot*> ref_map;
    ref_map.reserve(reference.size());
    for (const Snapshot& snap : reference) {
        ref_map.emplace(snap.address, &snap);
    }

    std::unordered_set<uint64_t> matched;
    matched.reserve(regions.size());

    for (const Region& region : regions) {
        if (!category_check(rules, region.category)) {
            continue;
        }
        const auto it = ref_map.find(region.address);
        if (it == ref_map.end() || it->second->size != region.size) {
            status |= ST_READONLY;
            changed_mask_out |= (1u << (region.category & 31u));
            continue;
        }
        std::vector<uint8_t> current(region.size);
        if (!read_memory(region.address, current.data(), region.size)) {
            status |= ST_FAULT;
            continue;
        }
        if (std::memcmp(current.data(), it->second->bytes.data(), region.size) != 0) {
            status |= ST_READONLY;
            changed_mask_out |= (1u << (region.category & 31u));
        }
        matched.insert(region.address);
    }

    for (const Snapshot& snap : reference) {
        if (matched.find(snap.address) == matched.end()) {
            status |= ST_READONLY;
            changed_mask_out |= (1u << (snap.category & 31u));
        }
    }

    return status;
}

}  // namespace sim_verify::native
