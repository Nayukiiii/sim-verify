#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace sim_verify::native {

/// Memory region descriptor matching the BDRC wire layout (16 bytes).
struct Region {
    uint64_t address{};
    uint32_t size{};
    uint16_t category{};
    uint16_t reserved{};
};

static_assert(sizeof(Region) == 16, "Region must match 16-byte wire layout");

/// Structured walk error codes aligned with sim_verify.boundary_recorder.WALK_ERRORS.
enum class WalkErrorCode : int {
    None = 0,
    ReadFault = 1,
    InvertedVector = 2,
    VectorOverLimit = 3,
    UnalignedVector = 4,
    UnknownTypeOrVTable = 5,
    MissingSentinel = 6,
    TreeTooDeep = 7,
    TreeOverLimit = 8,
    UnknownTreeKind = 9,
    RegionOverflow = 10,
};

/// Caller-owned output buffers populated during a graph walk.
struct WalkOutput {
    Region* regions{};
    uint32_t capacity{};
    uint32_t count{};
    uint64_t* children{};
    uint32_t child_capacity{};
    uint32_t child_count{};
    int error{};
    uint64_t detail{};
};

constexpr uint32_t kDefaultMaxRegions = 65536;
constexpr uint32_t kDefaultMaxChildren = 512;
constexpr uint32_t kSeenSlots = 16384;
constexpr uint32_t kTreeSeenSlots = 8192;

/// Open-addressed Fibonacci-hashed deduplication table for (base, type_index) pairs.
struct SeenTable {
    struct Key {
        uint64_t base{};
        uint32_t type{};
    };

    Key keys[kSeenSlots]{};
    uint8_t used[kSeenSlots]{};
    uint32_t count{};

    void clear() noexcept {
        std::memset(used, 0, sizeof(used));
        count = 0;
    }

    bool add(uint64_t base, uint32_t type) noexcept {
        const uint64_t h = (base >> 4) * 0x9E3779B97F4A7C15ULL ^ (static_cast<uint64_t>(type) * 0xBF58476D1CE4E5B9ULL);
        const uint32_t slot = static_cast<uint32_t>(h ^ (h >> 32)) & (kSeenSlots - 1u);
        for (uint32_t probe = 0; probe < kSeenSlots; ++probe) {
            const uint32_t at = (slot + probe) & (kSeenSlots - 1u);
            if (!used[at]) {
                used[at] = 1;
                keys[at] = Key{base, type};
                ++count;
                return true;
            }
            if (keys[at].base == base && keys[at].type == type) {
                return false;
            }
        }
        return false;
    }
};

/// Open-addressed Fibonacci-hashed deduplication table for tree node addresses.
struct TreeSeen {
    uint64_t keys[kTreeSeenSlots]{};
    uint8_t used[kTreeSeenSlots]{};

    void clear() noexcept {
        std::memset(used, 0, sizeof(used));
    }

    bool add(uint64_t base) noexcept {
        const uint64_t h = base * 0x9E3779B97F4A7C15ULL;
        const uint32_t slot = static_cast<uint32_t>(h ^ (h >> 32)) & (kTreeSeenSlots - 1u);
        for (uint32_t probe = 0; probe < kTreeSeenSlots; ++probe) {
            const uint32_t at = (slot + probe) & (kTreeSeenSlots - 1u);
            if (!used[at]) {
                used[at] = 1;
                keys[at] = base;
                return true;
            }
            if (keys[at] == base) {
                return false;
            }
        }
        return false;
    }
};

/// Declarative traversal operation kinds.
enum class WalkOpKind : uint32_t {
    Region = 0,
    Ptr = 1,
    Deref = 2,
    VecPtr = 3,
    Vec = 4,
    Records = 5,
    VTable = 6,
    Tree = 7,
    List = 8,
};

struct WalkOp {
    WalkOpKind kind{WalkOpKind::Region};
    uint32_t a{};
    uint32_t b{};
    uint32_t c{};
    uint32_t d{};
    const char* type{};
    const char* category{};
};

struct TypeRule {
    const char* name{};
    const WalkOp* ops{};
    uint32_t count{};
};

struct CategoryRule {
    const char* name{};
    bool check{};
    bool host_may_write{};
};

struct VTableRule {
    uint64_t address{};
    const char* type{};
};

struct GlobalRule {
    uint64_t address{};
    uint32_t size{};
    const char* name{};
    const char* category{};
};

struct IndirectGlobalRule {
    uint64_t pointer_address{};
    uint32_t offset{};
    uint32_t size{};
    const char* category{};
};

struct TreeSpec {
    uint32_t node_size{};
    uint32_t operand_offset{};
    uint32_t operand_size{};
    const char* category{};
    const char* operand_category{};
    uint8_t child_count[6]{0, 0, 0, 1, 2, 3};
    uint32_t child_offset[6][3]{
        {0, 0, 0},
        {0, 0, 0},
        {0, 0, 0},
        {0x10, 0, 0},
        {0x10, 0x18, 0},
        {0x10, 0x18, 0x20},
    };
};

struct WalkLimits {
    uint32_t children{512};
    uint32_t nodes{4096};
    uint32_t records{4096};
    uint32_t tree_depth{32};
    uint32_t tree_nodes{1024};
    uint32_t regions{kDefaultMaxRegions};
};

/// Declarative, allocation-free rule table describing a pointer graph.
struct RuleTable {
    const char* rules_sha256{};
    const CategoryRule* categories{};
    uint32_t category_count{};
    const TypeRule* types{};
    uint32_t type_count{};
    const VTableRule* vtables{};
    uint32_t vtable_count{};
    const GlobalRule* globals{};
    uint32_t global_count{};
    const IndirectGlobalRule* indirect_globals{};
    uint32_t indirect_global_count{};
    TreeSpec tree{};
    WalkLimits limits{};
};

/// SEH-guarded memory read; returns false without crashing on unmapped/faulting addresses.
bool read_memory(uint64_t address, void* destination, uint32_t size) noexcept;

/// SEH-guarded 64-bit read; returns 0 on fault.
uint64_t read_u64(uint64_t address) noexcept;

/// Page-stepping readability probe using ReadProcessMemory(GetCurrentProcess(), ...).
bool readable(uint64_t address, uint64_t size) noexcept;

/// Fast readability probe for <= 64-byte regions avoiding VirtualQuery/page-stepping overhead.
bool readable_quick(uint64_t address, uint64_t size) noexcept;

/// Sort regions by (address ascending, size descending) and coalesce overlapping (or adjacent) intervals.
std::vector<Region> merge_regions(const std::vector<Region>& regions, bool coalesce_adjacent = false);

/// Lookup helpers against a declarative RuleTable.
int category_index(const RuleTable& rules, const char* name) noexcept;
bool category_check(const RuleTable& rules, uint32_t index) noexcept;

/// Traverses an in-memory pointer graph using process-wide zero-heap BSS dedup tables.
class BoundaryWalker {
public:
    explicit BoundaryWalker(const RuleTable& rules) noexcept : rules_(rules) {}

    bool walk(uint64_t root_address, WalkOutput& output, const char* root_type = "unit") const noexcept;
    bool walk_globals(WalkOutput& output) const noexcept;
    const RuleTable& rules() const noexcept { return rules_; }

private:
    const RuleTable& rules_;
};

/// Convenience wrappers for walking a root unit or global regions.
bool walk_unit(const RuleTable& rules, uint64_t root_address, WalkOutput& output, const char* root_type = "unit") noexcept;
bool walk_globals(const RuleTable& rules, WalkOutput& output) noexcept;

}  // namespace sim_verify::native
