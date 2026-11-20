#include "sim_verify/boundary_session.h"
#include "sim_verify/boundary_walk.h"
#include "sim_verify/boundary_writer.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace sim_verify::native;

int g_failures = 0;

#define SIM_VERIFY_CHECK(cond)                                                                         \
    do {                                                                                            \
        if (!(cond)) {                                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                    \
            ++g_failures;                                                                           \
        }                                                                                           \
    } while (false)

uint32_t reference_crc32(const uint8_t* data, size_t size) {
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 1U) ? (0xEDB88320U ^ (crc >> 1)) : (crc >> 1);
        }
    }
    return crc ^ 0xFFFFFFFFU;
}

void test_seh_memory_safety() {
    uint8_t buf[16]{};
    SIM_VERIFY_CHECK(!read_memory(0x1000ULL, buf, sizeof(buf)));
    SIM_VERIFY_CHECK(!read_memory(0ULL, buf, 4));
    SIM_VERIFY_CHECK(read_u64(0x1000ULL) == 0ULL);
    SIM_VERIFY_CHECK(!readable(0x1000ULL, 16));
    SIM_VERIFY_CHECK(!readable_quick(0x1000ULL, 16));

    uint64_t stack_val = 0x1122334455667788ULL;
    const uint64_t addr = reinterpret_cast<uint64_t>(&stack_val);
    uint64_t read_back = 0;
    SIM_VERIFY_CHECK(read_memory(addr, &read_back, sizeof(read_back)));
    SIM_VERIFY_CHECK(read_back == stack_val);
    SIM_VERIFY_CHECK(read_u64(addr) == stack_val);
    SIM_VERIFY_CHECK(readable(addr, sizeof(stack_val)));
    SIM_VERIFY_CHECK(readable_quick(addr, sizeof(stack_val)));
}

void test_crc32_slicing8() {
    const char* vec = "123456789";
    SIM_VERIFY_CHECK(crc32_slicing8(0, vec, 9) == 0xCBF43926U);

    uint32_t inc = crc32_slicing8(0, vec, 4);
    inc = crc32_slicing8(inc, vec + 4, 5);
    SIM_VERIFY_CHECK(inc == 0xCBF43926U);

    uint8_t big[137]{};
    for (size_t i = 0; i < sizeof(big); ++i) {
        big[i] = static_cast<uint8_t>((i * 37 + 11) & 0xFFU);
    }
    SIM_VERIFY_CHECK(crc32_slicing8(0, big + 1, sizeof(big) - 1) == reference_crc32(big + 1, sizeof(big) - 1));
}

void test_walker_and_merge() {
    struct DerivedPayload {
        uint64_t vtable;
        uint32_t value;
        uint32_t pad;
    };
    struct ChildNode {
        uint32_t tag;
        uint32_t state;
    };
    struct TreeNode {
        int32_t kind;
        uint32_t pad;
        uint64_t operand;
        uint64_t child0;
        uint64_t child1;
        uint64_t child2;
    };
    struct ListLink {
        uint64_t next;
        uint64_t tag;
    };
    struct UnitObj {
        uint32_t cfg;         // +0x00
        uint32_t st;          // +0x04
        uint64_t child_ptr;   // +0x08
        uint64_t deref_ptr;   // +0x10
        uint64_t vecptr_b;    // +0x18
        uint64_t vecptr_e;    // +0x20
        uint64_t vec_b;       // +0x28
        uint64_t vec_e;       // +0x30
        uint64_t list_head_p; // +0x38
        uint64_t tree_ptr;    // +0x40
        uint64_t poly_ptr;    // +0x48
    };

    ChildNode c0{1, 10};
    ChildNode c1{2, 20};
    uint64_t child_ptrs[2] = {
        reinterpret_cast<uint64_t>(&c0),
        reinterpret_cast<uint64_t>(&c1),
    };
    uint8_t deref_buf[16]{};
    uint64_t vec_elems[2] = {100, 200};

    ListLink link2{0, 2};
    ListLink link1{reinterpret_cast<uint64_t>(&link2), 1};
    uint64_t list_anchor = reinterpret_cast<uint64_t>(&link1);

    uint8_t operand_buf[16]{};
    TreeNode leaf{1, 0, reinterpret_cast<uint64_t>(operand_buf), 0, 0, 0};
    TreeNode root_tree{3, 0, 0, reinterpret_cast<uint64_t>(&leaf), 0, 0};

    constexpr uint64_t kFakeVt = 0x55AA0001ULL;
    DerivedPayload poly{kFakeVt, 42, 0};

    UnitObj unit{};
    unit.cfg = 0xAABBCCDDu;
    unit.st = 0x11223344u;
    unit.child_ptr = reinterpret_cast<uint64_t>(&c0);
    unit.deref_ptr = reinterpret_cast<uint64_t>(deref_buf);
    unit.vecptr_b = reinterpret_cast<uint64_t>(child_ptrs);
    unit.vecptr_e = reinterpret_cast<uint64_t>(child_ptrs + 2);
    unit.vec_b = reinterpret_cast<uint64_t>(vec_elems);
    unit.vec_e = reinterpret_cast<uint64_t>(vec_elems + 2);
    unit.list_head_p = reinterpret_cast<uint64_t>(&list_anchor);
    unit.tree_ptr = reinterpret_cast<uint64_t>(&root_tree);
    unit.poly_ptr = reinterpret_cast<uint64_t>(&poly);

    static uint32_t g_scalar = 777;
    static uint32_t g_indirect_target[4] = {1, 2, 3, 4};
    static uint64_t g_indirect_ptr = reinterpret_cast<uint64_t>(g_indirect_target);

    const CategoryRule categories[] = {
        {"config", true, false},
        {"state", false, false},
        {"tree_node", true, false},
        {"global", false, true},
    };
    const WalkOp unit_ops[] = {
        {WalkOpKind::Region, 0x00, 4, 0, 0, nullptr, "config"},
        {WalkOpKind::Region, 0x04, 4, 0, 0, nullptr, "state"},
        {WalkOpKind::Ptr, 0x08, 0, 0, 0, "child", nullptr},
        {WalkOpKind::Deref, 0x10, 16, 0, 0, nullptr, "state"},
        {WalkOpKind::VecPtr, 0x18, 0, 16, 0, "child", "state"},
        {WalkOpKind::Vec, 0x28, 8, 16, 0, "none", "state"},
        {WalkOpKind::List, 0x38, 16, 0x28, 8, nullptr, "state"},
        {WalkOpKind::Ptr, 0x40, 0, 0, 0, "tree_root", nullptr},
        {WalkOpKind::Ptr, 0x48, 0, 0, 0, "poly", nullptr},
    };
    const WalkOp child_ops[] = {
        {WalkOpKind::Region, 0, sizeof(ChildNode), 0, 0, nullptr, "state"},
    };
    const WalkOp tree_ops[] = {
        {WalkOpKind::Tree, 0, 0, 0, 0, nullptr, nullptr},
    };
    const WalkOp poly_ops[] = {
        {WalkOpKind::VTable, 0, 0, 0, 0, nullptr, nullptr},
    };
    const WalkOp derived_ops[] = {
        {WalkOpKind::Region, 0, sizeof(DerivedPayload), 0, 0, nullptr, "config"},
    };
    const TypeRule types[] = {
        {"unit", unit_ops, sizeof(unit_ops) / sizeof(unit_ops[0])},
        {"child", child_ops, sizeof(child_ops) / sizeof(child_ops[0])},
        {"tree_root", tree_ops, sizeof(tree_ops) / sizeof(tree_ops[0])},
        {"poly", poly_ops, sizeof(poly_ops) / sizeof(poly_ops[0])},
        {"derived_payload", derived_ops, sizeof(derived_ops) / sizeof(derived_ops[0])},
    };
    const VTableRule vtables[] = {
        {kFakeVt, "derived_payload"},
    };
    const GlobalRule globals[] = {
        {reinterpret_cast<uint64_t>(&g_scalar), sizeof(g_scalar), "g_scalar", "global"},
    };
    const IndirectGlobalRule indirects[] = {
        {reinterpret_cast<uint64_t>(&g_indirect_ptr), 4, 8, "global"},
    };

    RuleTable rules{};
    rules.categories = categories;
    rules.category_count = 4;
    rules.types = types;
    rules.type_count = 5;
    rules.vtables = vtables;
    rules.vtable_count = 1;
    rules.globals = globals;
    rules.global_count = 1;
    rules.indirect_globals = indirects;
    rules.indirect_global_count = 1;
    rules.tree = TreeSpec{sizeof(TreeNode), 8, 16, "tree_node", "state", {0, 0, 0, 1, 2, 3},
                          {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {16, 0, 0}, {16, 24, 0}, {16, 24, 32}}};
    rules.limits = WalkLimits{64, 64, 64, 16, 64, 512};

    std::vector<Region> reg_buf(512);
    std::vector<uint64_t> child_buf(64);
    WalkOutput out{};
    out.regions = reg_buf.data();
    out.capacity = static_cast<uint32_t>(reg_buf.size());
    out.children = child_buf.data();
    out.child_capacity = static_cast<uint32_t>(child_buf.size());

    SIM_VERIFY_CHECK(walk_unit(rules, reinterpret_cast<uint64_t>(&unit), out));
    SIM_VERIFY_CHECK(out.error == 0);
    SIM_VERIFY_CHECK(out.child_count == 2);
    SIM_VERIFY_CHECK(out.count >= 8);

    // Wild pointer detection -> ST_WALK / WalkErrorCode::ReadFault (1)
    unit.child_ptr = 0x1000ULL;
    SIM_VERIFY_CHECK(!walk_unit(rules, reinterpret_cast<uint64_t>(&unit), out));
    SIM_VERIFY_CHECK(out.error == static_cast<int>(WalkErrorCode::ReadFault));
    unit.child_ptr = reinterpret_cast<uint64_t>(&c0);

    // Inverted vector detection -> WalkErrorCode::InvertedVector (2)
    unit.vec_e = unit.vec_b - 8;
    SIM_VERIFY_CHECK(!walk_unit(rules, reinterpret_cast<uint64_t>(&unit), out));
    SIM_VERIFY_CHECK(out.error == static_cast<int>(WalkErrorCode::InvertedVector));
    unit.vec_e = reinterpret_cast<uint64_t>(vec_elems + 2);

    // Globals walk
    SIM_VERIFY_CHECK(walk_globals(rules, out));
    SIM_VERIFY_CHECK(out.count == 2);

    // Region sorting & coalescing
    std::vector<Region> raw_regions = {
        {0x2000, 8, 1, 0},
        {0x1000, 4, 0, 0},
        {0x1002, 6, 0, 0},
        {0x1008, 4, 0, 0},
    };
    const auto merged_overlap = merge_regions(raw_regions, false);
    SIM_VERIFY_CHECK(merged_overlap.size() == 3);
    SIM_VERIFY_CHECK(merged_overlap[0].address == 0x1000 && merged_overlap[0].size == 8);
    SIM_VERIFY_CHECK(merged_overlap[1].address == 0x1008 && merged_overlap[1].size == 4);

    const auto merged_adj = merge_regions(raw_regions, true);
    SIM_VERIFY_CHECK(merged_adj.size() == 2);
    SIM_VERIFY_CHECK(merged_adj[0].address == 0x1000 && merged_adj[0].size == 12);
}

void test_overlap_tracker() {
    OverlapTracker tracker;
    constexpr uint64_t kUnitShared = 0xCAFE0001ULL;
    constexpr uint64_t kUnitA = 0xCAFE0002ULL;
    constexpr uint64_t kUnitB = 0xCAFE0003ULL;

    // Cross-thread overlap across two sites on the same unit taints both sides.
    std::atomic<int> phase{0};
    bool t1_enter_overlap = false;
    bool t2_enter_overlap = false;
    bool t1_exit_tainted = false;
    bool t2_exit_tainted = false;

    std::thread t1([&] {
        const uint32_t tid = GetCurrentThreadId();
        t1_enter_overlap = tracker.enter_slot(0, kUnitShared, tid, 0);
        phase.store(1, std::memory_order_release);
        while (phase.load(std::memory_order_acquire) < 2) {
            std::this_thread::yield();
        }
        t1_exit_tainted = tracker.take_slot_tainted(0, kUnitShared, tid, 0);
    });

    std::thread t2([&] {
        while (phase.load(std::memory_order_acquire) < 1) {
            std::this_thread::yield();
        }
        const uint32_t tid = GetCurrentThreadId();
        t2_enter_overlap = tracker.enter_slot(1, kUnitShared, tid, 1);
        t2_exit_tainted = tracker.take_slot_tainted(1, kUnitShared, tid, 1);
        phase.store(2, std::memory_order_release);
    });

    t1.join();
    t2.join();

    SIM_VERIFY_CHECK(!t1_enter_overlap);
    SIM_VERIFY_CHECK(t2_enter_overlap);
    SIM_VERIFY_CHECK(t1_exit_tainted);
    SIM_VERIFY_CHECK(t2_exit_tainted);

    // Distinct units across threads do not overlap.
    SIM_VERIFY_CHECK(!tracker.enter_slot(0, kUnitA, 101, 0));
    SIM_VERIFY_CHECK(!tracker.enter_slot(1, kUnitB, 202, 1));
    SIM_VERIFY_CHECK(!tracker.take_slot_tainted(0, kUnitA, 101, 0));
    SIM_VERIFY_CHECK(!tracker.take_slot_tainted(1, kUnitB, 202, 1));

    // Same-thread cross-site on the same unit does not overlap.
    SIM_VERIFY_CHECK(!tracker.enter_slot(0, kUnitA, 101, 0));
    SIM_VERIFY_CHECK(!tracker.enter_slot(1, kUnitA, 101, 1));
    SIM_VERIFY_CHECK(!tracker.take_slot_tainted(1, kUnitA, 101, 1));
    SIM_VERIFY_CHECK(!tracker.take_slot_tainted(0, kUnitA, 101, 0));

    // Per-thread recursion depth tracking -> ST_RECURSE.
    SIM_VERIFY_CHECK(!OverlapTracker::enter_recursion(0));
    SIM_VERIFY_CHECK(OverlapTracker::enter_recursion(0));
    SIM_VERIFY_CHECK(OverlapTracker::recursion_depth(0) == 2);
    SIM_VERIFY_CHECK(OverlapTracker::exit_recursion(0));
    SIM_VERIFY_CHECK(!OverlapTracker::exit_recursion(0));
    SIM_VERIFY_CHECK(OverlapTracker::recursion_depth(0) == 0);
}

void test_tls_rle_sampler() {
    using Sampler = TlsRleSampler<3>;
    volatile uint32_t scalar = 7;
    const uint64_t addr = reinterpret_cast<uint64_t>(&scalar);

    // Inactive fast path must ignore samples.
    Sampler::sample_u32(addr);
    SIM_VERIFY_CHECK(!Sampler::is_active());
    SIM_VERIFY_CHECK(Sampler::current().run_count == 0);

    Sampler::begin();
    SIM_VERIFY_CHECK(Sampler::is_active());
    Sampler::sample_u32(addr);
    Sampler::sample_u32(addr);
    Sampler::sample_u32(addr);
    scalar = 9;
    Sampler::sample_u32(addr);
    Sampler::sample_u32(addr);
    Sampler::record_value(11);
    SIM_VERIFY_CHECK(!Sampler::current().overflow);
    SIM_VERIFY_CHECK(!Sampler::current().read_failed);
    SIM_VERIFY_CHECK(Sampler::current().run_count == 3);
    SIM_VERIFY_CHECK(Sampler::current().runs[0].value == 7 && Sampler::current().runs[0].count == 3);
    SIM_VERIFY_CHECK(Sampler::current().runs[1].value == 9 && Sampler::current().runs[1].count == 2);
    SIM_VERIFY_CHECK(Sampler::current().runs[2].value == 11 && Sampler::current().runs[2].count == 1);

    // Fourth distinct run triggers overflow.
    Sampler::record_value(12);
    SIM_VERIFY_CHECK(Sampler::current().overflow);
    Sampler::end();
    SIM_VERIFY_CHECK(!Sampler::is_active());
}

void test_start_gate_and_readonly_verifier() {
    StartGate gate;
    SIM_VERIFY_CHECK(!gate.observe(false, 10));
    SIM_VERIFY_CHECK(!gate.observe(true, 10));
    SIM_VERIFY_CHECK(!gate.observe(true, 10));  // equal tick: holds streak=0
    SIM_VERIFY_CHECK(!gate.observe(true, 20));  // +1 -> streak=1
    SIM_VERIFY_CHECK(!gate.observe(true, 15));  // drop -> streak=0
    SIM_VERIFY_CHECK(!gate.observe(true, 25));  // +1 -> streak=1
    SIM_VERIFY_CHECK(gate.observe(true, 30));   // +2 -> opened
    SIM_VERIFY_CHECK(gate.opened);
    SIM_VERIFY_CHECK(gate.observe(false, 0));   // one-way: stays open

    struct Block {
        uint32_t cfg;
        uint32_t mut_state;
    } obj{0x12345678u, 1u};

    const CategoryRule cats[] = {
        {"config", true, false},
        {"state", false, false},
    };
    RuleTable rules{};
    rules.categories = cats;
    rules.category_count = 2;

    const std::vector<Region> regions = {
        {reinterpret_cast<uint64_t>(&obj.cfg), 4, 0, 0},
        {reinterpret_cast<uint64_t>(&obj.mut_state), 4, 1, 0},
    };
    std::vector<Snapshot> snap;
    ReadOnlyVerifier::capture(rules, regions, snap);
    SIM_VERIFY_CHECK(snap.size() == 1);

    obj.mut_state = 2u;  // check=false mutation is allowed
    uint32_t mask = 0;
    SIM_VERIFY_CHECK(ReadOnlyVerifier::verify(rules, regions, snap, mask) == 0);
    SIM_VERIFY_CHECK(mask == 0);

    obj.cfg = 0xDEADBEEFu;  // check=true mutation triggers ST_READONLY
    SIM_VERIFY_CHECK(ReadOnlyVerifier::verify(rules, regions, snap, mask) == ST_READONLY);
    SIM_VERIFY_CHECK((mask & 1u) != 0);
}

void test_writer_and_disk_floor(const std::filesystem::path& out_path) {
    uint64_t free_bytes = 0;
    SIM_VERIFY_CHECK(check_disk_floor(out_path, 1, &free_bytes));
    SIM_VERIFY_CHECK(free_bytes > 0);
    SIM_VERIFY_CHECK(!check_disk_floor(out_path, UINT64_MAX));

    struct UnitState {
        uint32_t cfg;
        uint32_t state;
    } unit{1u, 10u};

    const uint64_t unit_addr = reinterpret_cast<uint64_t>(&unit);
    const std::vector<Region> regions = {
        {unit_addr, 4, 0, 0},
        {unit_addr + 4, 4, 1, 0},
    };

    uint8_t rules_sha[32]{};
    uint8_t bin_sha[32]{};
    for (uint8_t i = 0; i < 32; ++i) {
        rules_sha[i] = static_cast<uint8_t>(i + 1);
        bin_sha[i] = static_cast<uint8_t>(0xA0u + i);
    }

    BoundaryWriter writer;
    SIM_VERIFY_CHECK(writer.open(out_path, R"({"source":"native_test"})", rules_sha, bin_sha, 10, 1000, 10000000ULL, 4242));
    writer.event(7, 1, 0, 0, 0, 100, 0);

    // Frame 0: entry & exit keep cfg=1 intact, state mutates 10 -> 20
    writer.frame_begin(0, 100, 100, 1100, 0, {});
    std::vector<uint8_t> entry_bytes(sizeof(unit));
    std::memcpy(entry_bytes.data(), &unit, sizeof(unit));
    writer.unit_block(0, 0, 0, 0, unit_addr, 0, 100, 0, regions, {{unit_addr, entry_bytes}});

    unit.state = 20u;
    std::vector<uint8_t> exit_bytes(sizeof(unit));
    std::memcpy(exit_bytes.data(), &unit, sizeof(unit));
    writer.unit_block(1, 0, 0, 0, unit_addr, 0, 100, 0, regions, {{unit_addr, exit_bytes}});
    writer.frame_end(0, 100, 0, 1, 0, 1200);

    // Frame 1: entry matches Frame 0 exit
    writer.frame_begin(1, 101, 100, 1300, 0, {});
    writer.unit_block(0, 0, 0, 0, unit_addr, 0, 100, 0, regions, {{unit_addr, exit_bytes}});
    unit.state = 30u;
    std::memcpy(exit_bytes.data(), &unit, sizeof(unit));
    writer.unit_block(1, 0, 0, 0, unit_addr, 0, 100, 0, regions, {{unit_addr, exit_bytes}});
    writer.frame_end(1, 100, 0, 1, 0, 1400);

    writer.close(R"({"status":"stopped"})");

    SIM_VERIFY_CHECK(!writer.faulted());
    SIM_VERIFY_CHECK(!writer.is_open());
    SIM_VERIFY_CHECK(writer.frames() == 2);
    SIM_VERIFY_CHECK(writer.invalid_frames() == 0);
    SIM_VERIFY_CHECK(writer.bytes_written() > kFileHeaderSize);
    SIM_VERIFY_CHECK(std::filesystem::exists(out_path));
}

}  // namespace

int main(int argc, char** argv) {
    test_seh_memory_safety();
    test_crc32_slicing8();
    test_walker_and_merge();
    test_overlap_tracker();
    test_tls_rle_sampler();
    test_start_gate_and_readonly_verifier();

    const std::filesystem::path out_path = (argc > 1)
        ? std::filesystem::path(argv[1])
        : (std::filesystem::temp_directory_path() / "sim_verify_native_test.bdrc");
    test_writer_and_disk_floor(out_path);

    if (g_failures == 0) {
        std::printf("ALL NATIVE RECORDER TESTS PASSED (stream=%ls)\n", out_path.wstring().c_str());
        return 0;
    }
    std::fprintf(stderr, "FAILED: %d check(s)\n", g_failures);
    return 1;
}
