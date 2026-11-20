#pragma once

#include "sim_verify/boundary_walk.h"
#include "sim_verify/boundary_writer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace sim_verify::native {

/// Frame and unit-block status bitmask aligned with sim_verify.boundary_recorder.STATUS_NAMES.
constexpr uint32_t ST_THREAD = 1;
constexpr uint32_t ST_READONLY = 2;
constexpr uint32_t ST_WALK = 4;
constexpr uint32_t ST_OVERFLOW = 8;
constexpr uint32_t ST_FAULT = 16;
constexpr uint32_t ST_OVERLAP = 32;
constexpr uint32_t ST_RUNAWAY = 64;
constexpr uint32_t ST_UNPAIRED = 128;
constexpr uint32_t ST_RECURSE = 256;

/// One-way monotonic start gate requiring two consecutive strict increases while active.
struct StartGate {
    bool opened{false};
    bool have{false};
    uint32_t streak{0};
    uint64_t last{0};

    bool observe(bool active, uint64_t logical_tick) noexcept;
    void reset() noexcept;
};

/// Tracks concurrent cross-thread per-unit overlap tainting and per-thread recursion depth.
class OverlapTracker {
public:
    static constexpr uint32_t kMaxSites = 4;

    struct InFlightSlot {
        uint64_t unit{};
        uint32_t thread{};
        uint32_t order{};
        bool tainted{};
    };

    OverlapTracker() = default;
    OverlapTracker(const OverlapTracker&) = delete;
    OverlapTracker& operator=(const OverlapTracker&) = delete;

    /// Marks colliding in-flight slots as tainted and returns true if an overlap occurred.
    /// Same-site collisions always overlap; cross-site collisions overlap only across distinct threads.
    bool mark_and_check_overlap(uint32_t site, uint64_t unit, uint32_t thread) noexcept;

    /// Records a new in-flight slot under the tracker lock.
    void push_slot(uint32_t site, uint64_t unit, uint32_t thread, uint32_t order, bool tainted) noexcept;

    /// Atomically checks/taints overlapping slots and pushes the new slot.
    bool enter_slot(uint32_t site, uint64_t unit, uint32_t thread, uint32_t order) noexcept;

    /// Removes the matching slot and returns whether it was tainted during flight.
    bool take_slot_tainted(uint32_t site, uint64_t unit, uint32_t thread, uint32_t order) noexcept;

    /// Returns true if `unit` is in flight on `primary_site` or on a different thread at another site.
    bool is_unit_in_flight(uint64_t unit, uint32_t current_thread, uint32_t primary_site = 0) const noexcept;

    size_t in_flight_count(uint32_t site) const noexcept;
    void clear() noexcept;

    /// Per-thread recursion depth tracking (returns true if call/exit is nested -> ST_RECURSE).
    static bool enter_recursion(uint32_t site) noexcept;
    static bool exit_recursion(uint32_t site) noexcept;
    static uint32_t recursion_depth(uint32_t site) noexcept;

private:
    bool mark_and_check_overlap_locked(uint32_t site, uint64_t unit, uint32_t thread) noexcept;

    mutable std::mutex mutex_;
    std::array<std::vector<InFlightSlot>, kMaxSites> slots_;
};

/// Snapshot of a check=true memory region taken at boundary entry.
struct Snapshot {
    uint64_t address{};
    uint32_t size{};
    uint16_t category{};
    std::vector<uint8_t> bytes;
};

/// Captures entry snapshots for check=true categories and detects ST_READONLY mutations at exit.
class ReadOnlyVerifier {
public:
    static void capture(const RuleTable& rules, const std::vector<Region>& regions, std::vector<Snapshot>& out);

    /// Compares current memory against `reference`. Returns ST_READONLY and/or ST_FAULT bits,
    /// and sets bits in `changed_mask_out` for each mutated category index (modulo 32).
    static uint32_t verify(const RuleTable& rules,
                           const std::vector<Region>& regions,
                           const std::vector<Snapshot>& reference,
                           uint32_t& changed_mask_out);
};

/// Single run-length encoded sample entry.
struct RleRun {
    uint32_t value{};
    uint32_t count{};
};

/// Lock-free thread-local RLE value sampler with a single TLS branch on the inactive fast path.
template <size_t MaxRuns = 4096>
class TlsRleSampler {
public:
    struct State {
        bool active{false};
        bool overflow{false};
        bool read_failed{false};
        uint32_t run_count{0};
        RleRun runs[MaxRuns]{};
    };

    static void begin() noexcept {
        State& s = state();
        s.run_count = 0;
        s.overflow = false;
        s.read_failed = false;
        s.active = true;
        tls_active() = true;
    }

    static void end() noexcept {
        tls_active() = false;
        state().active = false;
    }

    static void record_value(uint32_t value) noexcept {
        if (!tls_active()) {
            return;
        }
        State& s = state();
        if (!s.active) {
            return;
        }
        if (s.run_count > 0 && s.runs[s.run_count - 1].value == value) {
            ++s.runs[s.run_count - 1].count;
        } else if (s.run_count < MaxRuns) {
            s.runs[s.run_count++] = RleRun{value, 1u};
        } else {
            s.overflow = true;
        }
    }

    static void sample_u32(uint64_t address) noexcept {
        if (!tls_active()) {
            return;
        }
        uint32_t value = 0;
        if (!read_memory(address, &value, sizeof(value))) {
            state().read_failed = true;
            return;
        }
        record_value(value);
    }

    static const State& current() noexcept { return state(); }
    static bool is_active() noexcept { return tls_active(); }

private:
    static bool& tls_active() noexcept {
        thread_local bool active = false;
        return active;
    }

    static State& state() noexcept {
        thread_local State s{};
        return s;
    }
};

}  // namespace sim_verify::native
