// sbie_api.cpp — Sandboxie 驱动 API 的最小客户端
// ========================================================================
// 只实现一个动作：API_QUERY_DRIVER_INFO(info_class = -1) -> SCertInfo.State
// 该调用不要求调用方镜像已签名，也不需要 RTCore64 或任何物理映射。

#include "sbie_api.h"

#include <cstring>

namespace sbu {

namespace {

// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
constexpr uint32_t kSbieDrvCtlCode = 0x222007;

// core/drv/api_defs.h: API_QUERY_DRIVER_INFO = API_FIRST(0x12340000) + 0x44
constexpr uint64_t kApiQueryDriverInfo = 0x12340044ULL;

constexpr size_t kApiNumArgs = 8;

} // namespace

SbieApi::~SbieApi()
{
    if (h_ != INVALID_HANDLE_VALUE) {
        CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }
}

bool SbieApi::open()
{
    if (h_ != INVALID_HANDLE_VALUE)
        return true;

    // Qt 侧用 FILE_GENERIC_READ 打开；这里先按同样权限尝试，失败再要读写
    h_ = CreateFileW(L"\\\\.\\SandboxieDriverApi",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    if (h_ == INVALID_HANDLE_VALUE)
        h_ = CreateFileW(L"\\\\.\\SandboxieDriverApi",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);

    return h_ != INVALID_HANDLE_VALUE;
}

bool SbieApi::query_cert_state(uint64_t& state)
{
    state = 0;
    if (h_ == INVALID_HANDLE_VALUE)
        return false;

    // 驱动会 ProbeForRead(buf, sizeof(ULONG64)*API_NUM_ARGS, sizeof(ULONG64))，
    // 所以缓冲区要 8 字节对齐
    __declspec(align(8)) uint64_t parms[kApiNumArgs] = { 0 };
    parms[0] = kApiQueryDriverInfo;          // func_code
    parms[1] = uint64_t(0) - 1;              // info_class = -1 -> SCertInfo
    parms[2] = reinterpret_cast<uint64_t>(&state);
    parms[3] = sizeof(state);

    DWORD ret = 0;
    // METHOD_NEITHER：输入缓冲就是 parms 本身，驱动自己探测 info_data 指针；
    // 这种方法的 IOCTL 不允许传输出缓冲。
    if (!DeviceIoControl(h_, kSbieDrvCtlCode, parms, sizeof(parms), nullptr, 0, &ret, nullptr))
        return false;

    return true;
}

} // namespace sbu
