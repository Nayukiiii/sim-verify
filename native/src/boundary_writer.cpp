#include "sim_verify/boundary_writer.h"

#include <windows.h>

#include <cstring>
#include <vector>

namespace sim_verify::native {
namespace {

void put_bytes(std::vector<uint8_t>& out, const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    out.insert(out.end(), bytes, bytes + size);
}

template <class T>
void put_value(std::vector<uint8_t>& out, T value) {
    put_bytes(out, &value, sizeof(value));
}

void pack_blocks(std::vector<uint8_t>& out, const std::vector<MemoryBlock>& blocks, bool include_count) {
    if (include_count) {
        put_value<uint32_t>(out, static_cast<uint32_t>(blocks.size()));
    }
    for (const auto& block : blocks) {
        put_value<uint64_t>(out, block.first);
        put_value<uint32_t>(out, static_cast<uint32_t>(block.second.size()));
        put_value<uint32_t>(out, 0u);
        put_bytes(out, block.second.data(), block.second.size());
    }
}

uint32_t blocks_wire_bytes(const std::vector<MemoryBlock>& blocks) noexcept {
    uint32_t total = 4u;
    for (const auto& b : blocks) {
        total += 16u + static_cast<uint32_t>(b.second.size());
    }
    return total;
}

}  // namespace

uint32_t crc32_slicing8(uint32_t crc, const void* data, size_t size) noexcept {
    if (!data || size == 0) {
        return crc;
    }
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint32_t result = crc ^ 0xFFFFFFFFU;
    size_t i = 0;
    for (; i + 8 <= size; i += 8) {
        uint64_t chunk{};
        std::memcpy(&chunk, bytes + i, 8);
        const uint32_t lo = result ^ static_cast<uint32_t>(chunk);
        const uint32_t hi = static_cast<uint32_t>(chunk >> 32);
        result = kCrc32Table.t[7][lo & 0xFFU] ^
                 kCrc32Table.t[6][(lo >> 8) & 0xFFU] ^
                 kCrc32Table.t[5][(lo >> 16) & 0xFFU] ^
                 kCrc32Table.t[4][(lo >> 24) & 0xFFU] ^
                 kCrc32Table.t[3][hi & 0xFFU] ^
                 kCrc32Table.t[2][(hi >> 8) & 0xFFU] ^
                 kCrc32Table.t[1][(hi >> 16) & 0xFFU] ^
                 kCrc32Table.t[0][(hi >> 24) & 0xFFU];
    }
    for (; i < size; ++i) {
        result = kCrc32Table.t[0][(result ^ bytes[i]) & 0xFFU] ^ (result >> 8);
    }
    return result ^ 0xFFFFFFFFU;
}

bool check_disk_floor(const std::filesystem::path& path, uint64_t min_free_bytes, uint64_t* out_free_bytes) noexcept {
    std::wstring probe = path.wstring();
    ULARGE_INTEGER free_bytes{};
    if (!GetDiskFreeSpaceExW(probe.empty() ? L"." : probe.c_str(), &free_bytes, nullptr, nullptr)) {
        const std::filesystem::path parent = path.parent_path();
        const std::wstring parent_str = parent.empty() ? L"." : parent.wstring();
        if (!GetDiskFreeSpaceExW(parent_str.c_str(), &free_bytes, nullptr, nullptr)) {
            if (out_free_bytes) {
                *out_free_bytes = 0;
            }
            return false;
        }
    }
    if (out_free_bytes) {
        *out_free_bytes = static_cast<uint64_t>(free_bytes.QuadPart);
    }
    return static_cast<uint64_t>(free_bytes.QuadPart) >= min_free_bytes;
}

BoundaryWriter::~BoundaryWriter() {
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }
}

bool BoundaryWriter::open(const std::filesystem::path& path,
                          const std::string& info_json,
                          const uint8_t rules_sha[32],
                          const uint8_t binary_sha[32],
                          uint32_t frame_limit,
                          uint64_t start_qpc,
                          uint64_t frequency,
                          uint32_t pid) noexcept {
    if (file_) {
        set_fault("writer already open");
        return false;
    }
    fault_ = false;
    error_.clear();
    seq_ = 0;
    bytes_ = 0;
    ticks_ = 0;
    frames_ = 0;
    invalid_ = 0;
    chain_ = 0;

    const std::wstring wpath = path.wstring();
    if (_wfopen_s(&file_, wpath.c_str(), L"wb") != 0 || !file_) {
        file_ = nullptr;
        set_fault("cannot open output file");
        return false;
    }
    // 4 MiB synchronous stdio buffer: full buffer blocks the caller (backpressure) rather than dropping records.
    std::setvbuf(file_, nullptr, _IOFBF, kWriterBufferBytes);

    uint8_t header[kFileHeaderSize]{};
    std::memcpy(header, "BDRCREC1", 8);
    const uint32_t version = kStreamVersion;
    const uint32_t header_size = kFileHeaderSize;
    std::memcpy(header + 8, &version, 4);
    std::memcpy(header + 12, &header_size, 4);
    if (std::fwrite(header, 1, kFileHeaderSize, file_) != kFileHeaderSize) {
        set_fault("cannot write file header");
        return false;
    }
    bytes_ = kFileHeaderSize;

    const std::string text = info_json.empty() ? std::string("{}") : info_json;
    static constexpr uint8_t kZeroSha[32]{};
    std::vector<uint8_t> payload;
    payload.reserve(92 + text.size());
    put_bytes(payload, rules_sha ? rules_sha : kZeroSha, 32);
    put_bytes(payload, binary_sha ? binary_sha : kZeroSha, 32);
    put_value<uint32_t>(payload, frame_limit);
    put_value<uint32_t>(payload, pid);
    put_value<uint64_t>(payload, start_qpc);
    put_value<uint64_t>(payload, frequency);
    put_value<uint32_t>(payload, static_cast<uint32_t>(text.size()));
    put_bytes(payload, text.data(), text.size());
    return write_record(RecordKind::Run, payload.data(), static_cast<uint32_t>(payload.size()));
}

void BoundaryWriter::close(const std::string& run_end_json) noexcept {
    if (!file_) {
        return;
    }
    if (!fault_) {
        const std::string text = run_end_json.empty() ? std::string("{}") : run_end_json;
        std::vector<uint8_t> payload;
        payload.reserve(4 + text.size());
        put_value<uint32_t>(payload, static_cast<uint32_t>(text.size()));
        put_bytes(payload, text.data(), text.size());
        write_record(RecordKind::RunEnd, payload.data(), static_cast<uint32_t>(payload.size()));
    }
    if (!fault_) {
        std::vector<uint8_t> footer;
        footer.reserve(28);
        put_value<uint64_t>(footer, seq_ + 1);
        put_value<uint64_t>(footer, frames_);
        put_value<uint64_t>(footer, invalid_);
        put_value<uint32_t>(footer, chain_);
        write_record(RecordKind::Footer, footer.data(), static_cast<uint32_t>(footer.size()));
    }
    std::fflush(file_);
    std::fclose(file_);
    file_ = nullptr;
}

void BoundaryWriter::set_fault(const char* reason) noexcept {
    if (!fault_) {
        fault_ = true;
        error_ = reason ? reason : "write failure";
    }
}

bool BoundaryWriter::write_record(RecordKind kind, const void* payload, uint32_t size) noexcept {
    if (fault_ || !file_) {
        return false;
    }
    LARGE_INTEGER t0{};
    QueryPerformanceCounter(&t0);

    uint8_t header[kRecordHeaderSize]{};
    const uint32_t magic = kRecordMagic;
    const uint16_t kind_u16 = static_cast<uint16_t>(kind);
    const uint16_t flags = 0;
    const uint64_t sequence = seq_;
    std::memcpy(header, &magic, 4);
    std::memcpy(header + 4, &kind_u16, 2);
    std::memcpy(header + 6, &flags, 2);
    std::memcpy(header + 8, &size, 4);
    std::memcpy(header + 16, &sequence, 8);

    uint32_t crc = crc32_slicing8(0, header, kRecordHeaderSize);
    if (payload && size > 0) {
        crc = crc32_slicing8(crc, payload, size);
    }
    std::memcpy(header + 12, &crc, 4);

    if (std::fwrite(header, 1, kRecordHeaderSize, file_) != kRecordHeaderSize ||
        (size > 0 && std::fwrite(payload, 1, size, file_) != size)) {
        set_fault("short write");
        return false;
    }

    LARGE_INTEGER t1{};
    QueryPerformanceCounter(&t1);
    ticks_ += static_cast<uint64_t>(t1.QuadPart - t0.QuadPart);
    bytes_ += kRecordHeaderSize + size;
    if (kind != RecordKind::Footer) {
        chain_ = crc32_slicing8(chain_, &crc, 4);
    }
    ++seq_;
    return true;
}

void BoundaryWriter::frame_begin(uint64_t frame_seq,
                                 uint64_t tick,
                                 uint32_t thread,
                                 uint64_t qpc,
                                 int32_t epoch_tag,
                                 const std::vector<MemoryBlock>& globals) noexcept {
    const uint32_t globals_bytes = blocks_wire_bytes(globals);
    std::vector<uint8_t> payload;
    payload.reserve(40 + globals_bytes);
    put_value<uint64_t>(payload, frame_seq);
    put_value<uint64_t>(payload, tick);
    put_value<uint32_t>(payload, thread);
    put_value<uint32_t>(payload, 0u);
    put_value<uint64_t>(payload, qpc);
    put_value<int32_t>(payload, epoch_tag);
    put_value<uint32_t>(payload, globals_bytes);
    pack_blocks(payload, globals, true);
    write_record(RecordKind::Frame, payload.data(), static_cast<uint32_t>(payload.size()));
}

void BoundaryWriter::unit_block(uint8_t phase,
                                uint8_t status,
                                uint16_t walk_error,
                                uint32_t order,
                                uint64_t unit_address,
                                uint64_t ret_address,
                                uint32_t thread,
                                int32_t aux_param,
                                const std::vector<Region>& regions,
                                const std::vector<MemoryBlock>& blocks) noexcept {
    std::vector<uint8_t> payload;
    payload.reserve(40 + regions.size() * 16 + blocks_wire_bytes(blocks));
    put_value<uint8_t>(payload, phase);
    put_value<uint8_t>(payload, status);
    put_value<uint16_t>(payload, walk_error);
    put_value<uint32_t>(payload, order);
    put_value<uint64_t>(payload, unit_address);
    put_value<uint64_t>(payload, ret_address);
    put_value<uint32_t>(payload, thread);
    put_value<int32_t>(payload, aux_param);
    put_value<uint32_t>(payload, static_cast<uint32_t>(regions.size()));
    put_value<uint32_t>(payload, static_cast<uint32_t>(blocks.size()));
    for (const auto& region : regions) {
        put_value<uint64_t>(payload, region.address);
        put_value<uint32_t>(payload, region.size);
        put_value<uint16_t>(payload, region.category);
        put_value<uint16_t>(payload, 0u);
    }
    pack_blocks(payload, blocks, false);
    write_record(RecordKind::Unit, payload.data(), static_cast<uint32_t>(payload.size()));
}

void BoundaryWriter::event(uint16_t kind,
                           uint32_t value,
                           uint64_t object,
                           uint64_t ret_address,
                           uint64_t frame_seq,
                           uint32_t thread,
                           uint32_t flags) noexcept {
    std::vector<uint8_t> payload;
    payload.reserve(40);
    put_value<uint16_t>(payload, kind);
    put_value<uint16_t>(payload, 0u);
    put_value<uint32_t>(payload, value);
    put_value<uint64_t>(payload, object);
    put_value<uint64_t>(payload, ret_address);
    put_value<uint64_t>(payload, frame_seq);
    put_value<uint32_t>(payload, thread);
    put_value<uint32_t>(payload, flags);
    write_record(RecordKind::Event, payload.data(), static_cast<uint32_t>(payload.size()));
}

void BoundaryWriter::frame_end(uint64_t frame_seq,
                               uint32_t thread,
                               uint32_t status,
                               uint32_t units,
                               uint32_t changed_mask,
                               uint64_t qpc) noexcept {
    ++frames_;
    if (status != 0) {
        ++invalid_;
    }
    std::vector<uint8_t> payload;
    payload.reserve(32);
    put_value<uint64_t>(payload, frame_seq);
    put_value<uint32_t>(payload, thread);
    put_value<uint32_t>(payload, status);
    put_value<uint32_t>(payload, units);
    put_value<uint32_t>(payload, changed_mask);
    put_value<uint64_t>(payload, qpc);
    write_record(RecordKind::End, payload.data(), static_cast<uint32_t>(payload.size()));
}

}  // namespace sim_verify::native
