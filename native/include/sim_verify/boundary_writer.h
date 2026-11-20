#pragma once

#include "sim_verify/boundary_walk.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace sim_verify::native {

using MemoryBlock = std::pair<uint64_t, std::vector<uint8_t>>;

constexpr uint32_t kStreamVersion = 1;
constexpr uint32_t kFileHeaderSize = 256;
constexpr uint32_t kRecordHeaderSize = 32;
constexpr uint32_t kRecordMagic = 0x43524442U;  // 'BDRC' little-endian
constexpr size_t kWriterBufferBytes = 4u << 20;  // 4 MiB blocking stdio buffer

enum class RecordKind : uint16_t {
    Run = 1,
    Frame = 2,
    Unit = 3,
    Event = 4,
    End = 5,
    RunEnd = 6,
    Footer = 0xFFFF,
};

/// Compile-time Slicing-by-8 IEEE CRC32 lookup table.
struct Crc32Slicing8Table {
    uint32_t t[8][256]{};

    constexpr Crc32Slicing8Table() noexcept {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t value = i;
            for (int bit = 0; bit < 8; ++bit) {
                value = (value & 1U) ? (0xEDB88320U ^ (value >> 1)) : (value >> 1);
            }
            t[0][i] = value;
        }
        for (int slice = 1; slice < 8; ++slice) {
            for (uint32_t i = 0; i < 256; ++i) {
                const uint32_t prev = t[slice - 1][i];
                t[slice][i] = (prev >> 8) ^ t[0][prev & 0xFFU];
            }
        }
    }
};

inline constexpr Crc32Slicing8Table kCrc32Table{};
static_assert(kCrc32Table.t[0][1] == 0x77073096U, "CRC32 table must be constexpr");

/// Incremental Slicing-by-8 IEEE CRC32 (matches Python zlib.crc32).
uint32_t crc32_slicing8(uint32_t crc, const void* data, size_t size) noexcept;

/// Checks whether the volume containing `path` has at least `min_free_bytes` available.
bool check_disk_floor(const std::filesystem::path& path, uint64_t min_free_bytes, uint64_t* out_free_bytes = nullptr) noexcept;

/// Synchronous CRC-chained binary boundary stream writer (BDRCREC1).
class BoundaryWriter {
public:
    BoundaryWriter() = default;
    ~BoundaryWriter();

    BoundaryWriter(const BoundaryWriter&) = delete;
    BoundaryWriter& operator=(const BoundaryWriter&) = delete;

    bool open(const std::filesystem::path& path,
              const std::string& info_json,
              const uint8_t rules_sha[32],
              const uint8_t binary_sha[32],
              uint32_t frame_limit = 0,
              uint64_t start_qpc = 0,
              uint64_t frequency = 10000000ULL,
              uint32_t pid = 0) noexcept;

    void close(const std::string& run_end_json = "{}") noexcept;

    void frame_begin(uint64_t frame_seq,
                     uint64_t tick,
                     uint32_t thread,
                     uint64_t qpc = 0,
                     int32_t epoch_tag = 0,
                     const std::vector<MemoryBlock>& globals = {}) noexcept;

    void unit_block(uint8_t phase,
                    uint8_t status,
                    uint16_t walk_error,
                    uint32_t order,
                    uint64_t unit_address,
                    uint64_t ret_address,
                    uint32_t thread,
                    int32_t aux_param,
                    const std::vector<Region>& regions,
                    const std::vector<MemoryBlock>& blocks) noexcept;

    void event(uint16_t kind,
               uint32_t value,
               uint64_t object,
               uint64_t ret_address,
               uint64_t frame_seq,
               uint32_t thread,
               uint32_t flags = 0) noexcept;

    void frame_end(uint64_t frame_seq,
                   uint32_t thread,
                   uint32_t status,
                   uint32_t units,
                   uint32_t changed_mask = 0,
                   uint64_t qpc = 0) noexcept;

    bool is_open() const noexcept { return file_ != nullptr; }
    bool faulted() const noexcept { return fault_; }
    const std::string& error() const noexcept { return error_; }
    uint64_t bytes_written() const noexcept { return bytes_; }
    uint64_t write_ticks() const noexcept { return ticks_; }
    uint64_t frames() const noexcept { return frames_; }
    uint64_t invalid_frames() const noexcept { return invalid_; }
    uint64_t record_count() const noexcept { return seq_; }
    uint32_t chain_crc() const noexcept { return chain_; }

private:
    bool write_record(RecordKind kind, const void* payload, uint32_t size) noexcept;
    void set_fault(const char* reason) noexcept;

    std::FILE* file_{};
    bool fault_{};
    std::string error_;
    uint64_t seq_{};
    uint64_t bytes_{};
    uint64_t ticks_{};
    uint64_t frames_{};
    uint64_t invalid_{};
    uint32_t chain_{};
};

}  // namespace sim_verify::native
