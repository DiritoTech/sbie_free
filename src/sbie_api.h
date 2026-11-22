#pragma once
// Sandboxie 驱动 API 的最小客户端：只用来读驱动内部的 Verify_CertInfo 状态。
//
// 设备名 / CTL_CODE / 报文布局取自 Sandboxie 源码：
//   core/drv/api_defs.h : API_DEVICE_NAME, API_SBIEDRV_CTLCODE, API_NUM_ARGS
//   QSbieAPI/SbieAPI.cpp: CSbieAPI::GetDriverInfo
//
// 这条通道不经过任何物理映射，因此在“HAL 不让 MmMapIoSpace / PhysicalMemory 映射”
// 的机器上仍然可用。

#include <cstdint>
#include <windows.h>

namespace sbu {

class SbieApi {
public:
    ~SbieApi();

    // 打开 \\\\.\\SandboxieDriverApi（需要 SbieSvc 已启动）
    bool open();

    // 读取 SCertInfo.State（info_class = -1）
    bool query_cert_state(uint64_t& state);

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

} // namespace sbu
