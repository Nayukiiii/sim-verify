#include "sim_verify/boundary_walk.h"

#include <windows.h>

#include <algorithm>
#include <cstring>

namespace sim_verify::native {
namespace {

// Process-wide zero-heap BSS deduplication tables (~344 KiB total). Keeping them in
// static BSS avoids blowing small host thread stacks during hook-path traversals.
SeenTable g_seen;
TreeSeen g_trees;
SRWLOCK g_walk_lock = SRWLOCK_INIT;

const TypeRule* find_type(const RuleTable& rules, const char* name) noexcept {
    if (!name || !rules.types) {
        return nullptr;
    }
    for (uint32_t i = 0; i < rules.type_count; ++i) {
        if (rules.types[i].name && std::strcmp(rules.types[i].name, name) == 0) {
            return &rules.types[i];
        }
    }
    return nullptr;
}

const char* find_vtable_type(const RuleTable& rules, uint64_t vt) noexcept {
    if (!rules.vtables) {
        return nullptr;
    }
    for (uint32_t i = 0; i < rules.vtable_count; ++i) {
        if (rules.vtables[i].address == vt) {
            return rules.vtables[i].type;
        }
    }
    return nullptr;
}

bool add_global_region(const RuleTable& rules, WalkOutput& output, uint64_t address, uint64_t size, const char* category) noexcept {
    if (output.error) {
        return false;
    }
    if (!size) {
        return true;
    }
    if (size > 0xFFFFFFFFULL) {
        output.error = static_cast<int>(WalkErrorCode::RegionOverflow);
        output.detail = address;
        return false;
    }
    const int cat = category_index(rules, category);
    if (cat < 0) {
        output.error = static_cast<int>(WalkErrorCode::RegionOverflow);
        output.detail = address;
        return false;
    }
    const uint32_t region_limit = rules.limits.regions ? rules.limits.regions : kDefaultMaxRegions;
    if (!output.regions || output.count >= output.capacity || output.count >= region_limit) {
        output.error = static_cast<int>(WalkErrorCode::RegionOverflow);
        output.detail = output.count;
        return false;
    }
    if (!readable_quick(address, size)) {
        output.error = static_cast<int>(WalkErrorCode::ReadFault);
        output.detail = address;
        return false;
    }
    output.regions[output.count++] = Region{address, static_cast<uint32_t>(size), static_cast<uint16_t>(cat), 0};
    return true;
}

class WalkerEngine {
public:
    WalkerEngine(const RuleTable& rules, WalkOutput& out, SeenTable& seen, TreeSeen& trees) noexcept
        : rules_(rules), out_(out), seen_(seen), trees_(trees) {}

    void visit(uint64_t base, const char* type_name) noexcept {
        if (out_.error) {
            return;
        }
        const TypeRule* type = find_type(rules_, type_name);
        if (!type) {
            fail(WalkErrorCode::UnknownTypeOrVTable, base);
            return;
        }
        const uint32_t type_idx = static_cast<uint32_t>(type - rules_.types);
        if (!seen_.add(base, type_idx)) {
            return;
        }
        for (uint32_t i = 0; i < type->count; ++i) {
            const WalkOp& op = type->ops[i];
            switch (op.kind) {
            case WalkOpKind::Region:
                add(base + op.a, op.b, op.category);
                break;

            case WalkOpKind::Ptr: {
                uint64_t p{};
                if (!read_qword(base + op.a, p)) {
                    return;
                }
                if (p) {
                    visit(p, op.type);
                }
                break;
            }

            case WalkOpKind::Deref: {
                uint64_t p{};
                if (!read_qword(base + op.a, p)) {
                    return;
                }
                if (p) {
                    add(p, op.b, op.category);
                }
                break;
            }

            case WalkOpKind::VecPtr: {
                uint64_t b{};
                uint64_t e{};
                if (!read_vec(base + op.a, op.c, 8, b, e)) {
                    return;
                }
                add(b, e - b, op.category);
                if (out_.error) {
                    return;
                }
                for (uint64_t p = b; p < e; p += 8) {
                    uint64_t child{};
                    if (!read_qword(p, child)) {
                        return;
                    }
                    if (type->name && std::strcmp(type->name, "unit") == 0 &&
                        op.type && std::strcmp(op.type, "child") == 0) {
                        const uint32_t child_limit = rules_.limits.children ? rules_.limits.children : kDefaultMaxChildren;
                        if (out_.children && out_.child_count < out_.child_capacity && out_.child_count < child_limit) {
                            out_.children[out_.child_count++] = child;
                        }
                    }
                    if (child) {
                        visit(child, op.type);
                    }
                }
                break;
            }

            case WalkOpKind::Vec: {
                uint64_t b{};
                uint64_t e{};
                if (!read_vec(base + op.a, op.c, op.b, b, e)) {
                    return;
                }
                add(b, e - b, op.category);
                if (out_.error) {
                    return;
                }
                if (op.type && std::strcmp(op.type, "none") != 0 && op.b > 0) {
                    for (uint64_t p = b; p < e; p += op.b) {
                        visit(p, op.type);
                    }
                }
                break;
            }

            case WalkOpKind::Records:
                walk_records(base + op.a, op.b ? op.b : 32u, op.c, op.category);
                break;

            case WalkOpKind::VTable: {
                uint64_t vt{};
                if (!read_qword(base + op.a, vt)) {
                    return;
                }
                const char* target = find_vtable_type(rules_, vt);
                if (!target) {
                    fail(WalkErrorCode::UnknownTypeOrVTable, vt);
                    return;
                }
                visit(base, target);
                break;
            }

            case WalkOpKind::Tree:
                walk_tree(base, 0);
                break;

            case WalkOpKind::List: {
                // Bounded singly-linked list traversal whose step count is bounded by
                // the parallel element vector at (base + op.c) with stride op.d.
                uint64_t p{};
                if (!read_qword(base + op.a, p)) {
                    return;
                }
                if (!p) {
                    break;
                }
                add(p, 16, op.category);
                uint64_t h{};
                if (out_.error || !read_qword(p, h)) {
                    return;
                }
                add(h, 16, op.category);
                uint64_t vb{};
                uint64_t ve{};
                const uint32_t node_limit = rules_.limits.nodes ? rules_.limits.nodes : 4096u;
                if (out_.error || !op.d || !read_vec(base + op.c, node_limit, op.d, vb, ve)) {
                    return;
                }
                const uint64_t n = (ve - vb) / op.d;
                uint64_t prev = h;
                for (uint64_t step = 1; step < n; ++step) {
                    uint64_t node{};
                    if (!read_qword(prev, node)) {
                        return;
                    }
                    add(node, op.b, op.category);
                    if (out_.error) {
                        return;
                    }
                    prev = node;
                }
                break;
            }

            default:
                fail(WalkErrorCode::RegionOverflow, base);
                return;
            }
            if (out_.error) {
                return;
            }
        }
    }

private:
    void fail(WalkErrorCode code, uint64_t detail = 0) noexcept {
        if (!out_.error) {
            out_.error = static_cast<int>(code);
            out_.detail = detail;
        }
    }

    bool read_qword(uint64_t address, uint64_t& value) noexcept {
        if (!read_memory(address, &value, 8)) {
            fail(WalkErrorCode::ReadFault, address);
            return false;
        }
        return true;
    }

    void add(uint64_t address, uint64_t size, const char* category) noexcept {
        if (out_.error || !size) {
            return;
        }
        if (size > 0xFFFFFFFFULL) {
            fail(WalkErrorCode::RegionOverflow, address);
            return;
        }
        const int cat = category_index(rules_, category);
        if (cat < 0) {
            fail(WalkErrorCode::RegionOverflow, address);
            return;
        }
        const uint32_t region_limit = rules_.limits.regions ? rules_.limits.regions : kDefaultMaxRegions;
        if (!out_.regions || out_.count >= out_.capacity || out_.count >= region_limit) {
            fail(WalkErrorCode::RegionOverflow, out_.count);
            return;
        }
        if (!readable(address, size)) {
            fail(WalkErrorCode::ReadFault, address);
            return;
        }
        out_.regions[out_.count++] = Region{address, static_cast<uint32_t>(size), static_cast<uint16_t>(cat), 0};
    }

    bool read_vec(uint64_t at, uint32_t cap, uint32_t align, uint64_t& begin, uint64_t& end) noexcept {
        uint64_t b{};
        uint64_t e{};
        if (!read_qword(at, b) || !read_qword(at + 8, e)) {
            return false;
        }
        if (e < b) {
            fail(WalkErrorCode::InvertedVector, at);
            return false;
        }
        if (align && ((e - b) % align) != 0) {
            fail(WalkErrorCode::UnalignedVector, at);
            return false;
        }
        if (align && (e - b) / align > cap) {
            fail(WalkErrorCode::VectorOverLimit, at);
            return false;
        }
        begin = b;
        end = e;
        return true;
    }

    uint32_t read_record_list(uint64_t at, uint32_t stride, uint32_t cap, uint64_t& begin) noexcept {
        uint64_t b{};
        uint64_t e{};
        if (!read_qword(at, b) || !read_qword(at + 8, e)) {
            return 0;
        }
        begin = b;
        if (b == e) {
            return 0;
        }
        if (e < b || stride < 4) {
            fail(WalkErrorCode::InvertedVector, at);
            return 0;
        }
        for (uint32_t i = 0; i <= cap; ++i) {
            uint32_t kind{};
            if (!read_memory(b + static_cast<uint64_t>(stride) * i, &kind, 4)) {
                fail(WalkErrorCode::ReadFault, b + static_cast<uint64_t>(stride) * i);
                return 0;
            }
            if (kind == 0) {
                return i + 1;
            }
        }
        fail(WalkErrorCode::MissingSentinel, at);
        return 0;
    }

    void walk_records(uint64_t at, uint32_t stride, uint32_t cap, const char* category) noexcept {
        uint64_t begin{};
        const uint32_t n = read_record_list(at, stride, cap, begin);
        if (n && !out_.error) {
            add(begin, static_cast<uint64_t>(stride) * n, category);
        }
    }

    void walk_tree(uint64_t node, uint32_t depth) noexcept {
        if (out_.error) {
            return;
        }
        const uint32_t depth_limit = rules_.limits.tree_depth ? rules_.limits.tree_depth : 32u;
        const uint32_t node_limit = rules_.limits.tree_nodes ? rules_.limits.tree_nodes : 1024u;
        if (depth > depth_limit) {
            fail(WalkErrorCode::TreeTooDeep, node);
            return;
        }
        if (!trees_.add(node)) {
            return;
        }
        if (++tree_nodes_ > node_limit) {
            fail(WalkErrorCode::TreeOverLimit, node);
            return;
        }
        add(node, rules_.tree.node_size, rules_.tree.category);
        int32_t kind{};
        if (!read_memory(node, &kind, 4)) {
            fail(WalkErrorCode::ReadFault, node);
            return;
        }
        if (kind < 0 || kind > 5) {
            fail(WalkErrorCode::UnknownTreeKind, node);
            return;
        }
        if ((kind == 1 || kind == 2) && rules_.tree.operand_size > 0 && rules_.tree.operand_category) {
            uint64_t operand{};
            if (!read_qword(node + rules_.tree.operand_offset, operand)) {
                return;
            }
            if (operand) {
                add(operand, rules_.tree.operand_size, rules_.tree.operand_category);
            }
        }
        const uint32_t count = rules_.tree.child_count[kind];
        for (uint32_t i = 0; i < count && i < 3; ++i) {
            uint64_t child{};
            if (!read_qword(node + rules_.tree.child_offset[kind][i], child)) {
                return;
            }
            if (child) {
                walk_tree(child, depth + 1);
            }
        }
    }

    const RuleTable& rules_;
    WalkOutput& out_;
    SeenTable& seen_;
    TreeSeen& trees_;
    uint32_t tree_nodes_{};
};

}  // namespace

bool read_memory(uint64_t address, void* destination, uint32_t size) noexcept {
    if (!address || !destination || !size) {
        return false;
    }
    if (address + size < address) {
        return false;
    }
    __try {
        std::memcpy(destination, reinterpret_cast<const void*>(static_cast<uintptr_t>(address)), size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

uint64_t read_u64(uint64_t address) noexcept {
    uint64_t value{};
    read_memory(address, &value, sizeof(value));
    return value;
}

bool readable(uint64_t address, uint64_t size) noexcept {
    if (!address || !size) {
        return false;
    }
    const uint64_t end = address + size;
    if (end < address) {
        return false;
    }
    const HANDLE self = GetCurrentProcess();
    uint64_t at = address;
    while (at < end) {
        uint8_t probe{};
        SIZE_T copied = 0;
        if (ReadProcessMemory(self, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(at)), &probe, 1, &copied) == 0 ||
            copied != 1) {
            return false;
        }
        const uint64_t next = (at | 0xFFFULL) + 1ULL;
        if (next <= at) {
            break;
        }
        at = next;
    }
    return true;
}

bool readable_quick(uint64_t address, uint64_t size) noexcept {
    if (!address || !size || address + size < address) {
        return false;
    }
    if (size > 64) {
        return readable(address, size);
    }
    uint8_t scratch[64]{};
    SIZE_T copied = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(address)),
                             scratch, static_cast<SIZE_T>(size), &copied) != 0 &&
           copied == size;
}

std::vector<Region> merge_regions(const std::vector<Region>& regions, bool coalesce_adjacent) {
    std::vector<Region> sorted(regions);
    std::sort(sorted.begin(), sorted.end(), [](const Region& a, const Region& b) {
        if (a.address != b.address) {
            return a.address < b.address;
        }
        return a.size > b.size;
    });
    std::vector<Region> out;
    out.reserve(sorted.size());
    for (const Region& r : sorted) {
        if (out.empty()) {
            out.push_back(r);
            continue;
        }
        Region& back = out.back();
        const uint64_t back_end = back.address + back.size;
        const bool overlaps = coalesce_adjacent ? (r.address <= back_end) : (r.address < back_end);
        if (overlaps) {
            const uint64_t r_end = r.address + r.size;
            if (r_end > back_end) {
                back.size = static_cast<uint32_t>(r_end - back.address);
            }
        } else {
            out.push_back(r);
        }
    }
    return out;
}

int category_index(const RuleTable& rules, const char* name) noexcept {
    if (!name || !rules.categories) {
        return -1;
    }
    for (uint32_t i = 0; i < rules.category_count; ++i) {
        if (rules.categories[i].name && std::strcmp(rules.categories[i].name, name) == 0) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool category_check(const RuleTable& rules, uint32_t index) noexcept {
    return rules.categories && index < rules.category_count && rules.categories[index].check;
}

bool BoundaryWalker::walk(uint64_t root_address, WalkOutput& output, const char* root_type) const noexcept {
    output.count = 0;
    output.child_count = 0;
    output.error = 0;
    output.detail = 0;
    if (!root_address) {
        output.error = static_cast<int>(WalkErrorCode::ReadFault);
        return false;
    }
    AcquireSRWLockExclusive(&g_walk_lock);
    g_seen.clear();
    g_trees.clear();
    WalkerEngine engine(rules_, output, g_seen, g_trees);
    engine.visit(root_address, root_type ? root_type : "unit");
    ReleaseSRWLockExclusive(&g_walk_lock);
    return output.error == 0;
}

bool BoundaryWalker::walk_globals(WalkOutput& output) const noexcept {
    output.count = 0;
    output.child_count = 0;
    output.error = 0;
    output.detail = 0;
    if (rules_.globals) {
        for (uint32_t i = 0; i < rules_.global_count; ++i) {
            const GlobalRule& g = rules_.globals[i];
            const char* cat = g.category ? g.category : "global";
            if (!add_global_region(rules_, output, g.address, g.size, cat)) {
                return false;
            }
        }
    }
    if (rules_.indirect_globals) {
        const HANDLE self = GetCurrentProcess();
        for (uint32_t i = 0; i < rules_.indirect_global_count; ++i) {
            const IndirectGlobalRule& ig = rules_.indirect_globals[i];
            uint64_t target = 0;
            SIZE_T copied = 0;
            if (ReadProcessMemory(self, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(ig.pointer_address)),
                                  &target, sizeof(target), &copied) == 0 ||
                copied != sizeof(target)) {
                output.error = static_cast<int>(WalkErrorCode::ReadFault);
                output.detail = ig.pointer_address;
                return false;
            }
            if (target != 0) {
                const char* cat = ig.category ? ig.category : "global";
                if (!add_global_region(rules_, output, target + ig.offset, ig.size, cat)) {
                    return false;
                }
            }
        }
    }
    return output.error == 0;
}

bool walk_unit(const RuleTable& rules, uint64_t root_address, WalkOutput& output, const char* root_type) noexcept {
    return BoundaryWalker(rules).walk(root_address, output, root_type);
}

bool walk_globals(const RuleTable& rules, WalkOutput& output) noexcept {
    return BoundaryWalker(rules).walk_globals(output);
}

}  // namespace sim_verify::native
