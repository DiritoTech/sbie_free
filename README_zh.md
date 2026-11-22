# SandBoxie Unlocker

[![Build & Release](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml/badge.svg)](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml)

用于生成硬件锁定（节点锁定）的 Sandboxie-Plus 赞助者证书，并应用对应内存补丁的 Windows 图形界面工具。

**语言：** [English](README.md) | 简体中文

## 概述

SandBoxie Unlocker 会：

1. 读取当前机器的硬件标识。
2. 生成 ECC 密钥对和节点锁定的 `Certificate.dat`。
3. 加载 `RTCore64.sys`，并补丁 `SbieDrv.sys` 内存中的公钥。
4. 重签 Sandboxie 可执行文件的 `.sig`，使补丁后的驱动接受生成的证书。
5. 把 `Certificate.dat` 放进 Sandboxie 安装目录。
6. 操作结束后移除临时驱动服务。

> **仅供学习与研究。** 驱动补丁只存在于内存中，系统重启后失效。修改 Windows 安全设置或加载存在漏洞的内核驱动可能导致系统不稳定甚至蓝屏。请仅在可以接受数据丢失的测试环境中使用。

## 版本兼容性

| Sandboxie-Plus | 公钥位置 | 补丁方式 |
|---|---|---|
| 1.18.x 及更早 | 可写的 `.data` 段（`static UCHAR`） | 内核虚拟地址直接写 |
| 1.19.x 及更新 | **只读的 `.rdata` 段**（`static const UCHAR`，官方用于防运行期篡改） | 页表翻译出物理地址后 `MmMapIoSpace` + 物理写 |

1.19 起官方把 `KphpTrustedPublicKey` 声明为 `const`，编译器将其放进只读段，继续按虚拟地址写入会触发内核页错误（蓝屏）。因此工具会自动：

1. 扫描内存镜像的**所有**段定位 `"ECS1" + 0x20` 公钥特征（并用 P-256 曲线点校验排除误报）；
2. 读 `ntoskrnl!PsInitialSystemProcess` → `_EPROCESS.DirectoryTableBase` 取得 CR3；
3. 走页表把公钥虚拟地址翻译成物理地址；
4. 用驱动的 `MmMapIoSpace` 映射该物理页后写入新公钥——物理写不受页表写保护限制。

两条路径由同一份代码覆盖，无需手动选择版本。

## 安全检测

开始注册前，程序会检查：

- 内存完整性（HVCI）
- Microsoft 易受攻击驱动阻止列表
- 内核模式硬件强制堆栈保护
- 已知冲突安全软件，包括卡巴斯基、360 和火绒进程

检测到上述情况时，程序会阻止操作。当前实现中，如果无法创建进程快照，程序会按“未发现冲突进程”处理并继续。

## 目录结构

```text
.
├── CMakeLists.txt
├── README.md
├── README_zh.md
├── src/
│   ├── core.cpp                    # 证书生成、驱动补丁、重签与还原
│   ├── core.h
│   ├── main.cpp                    # Win32 GUI
│   ├── windows_security_check.cpp  # 驱动兼容性与安全软件检测
│   └── windows_security_check.h
└── third_party/
    ├── rtcore.h                    # RTCore64 ioctl 封装
    └── RTCore64.sys
```

## 环境要求

- Windows x64
- Visual Studio 2022 或 Build Tools 2022，包含 MSVC 工具链与 Windows SDK
- CMake 3.15 或更高版本
- `third_party/RTCore64.sys`

构建成功后，CMake 会自动把 `RTCore64.sys` 复制到可执行文件所在目录。

## 构建

### Visual Studio 生成器

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

输出：

```text
build\Release\SandBoxieUnlocker.exe
build\Release\RTCore64.sys
```

### Ninja 生成器

需要先初始化 x64 MSVC 环境。例如：

```powershell
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"" && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build"
```

输出：

```text
build\SandBoxieUnlocker.exe
build\RTCore64.sys
```

如果你使用其他 Visual Studio 版本，请相应调整 `vcvars64.bat` 路径。

## 使用方法

1. 把 `SandBoxieUnlocker.exe` 和 `RTCore64.sys` 放到 Sandboxie 安装目录。
2. 以管理员身份运行 `SandBoxieUnlocker.exe`；未提权时程序会自动请求 UAC。
3. 填写姓名，选择级别（`STANDARD` / `ADVANCED` / `ADVANCED1` / `HUGE`），并输入有效天数。
4. 点击 **注册**。
5. 日志出现 `9/9 全部完成` 后**重启 Sandboxie-Plus**（`Certificate.dat` 已自动放入安装目录，无需手动复制）。

> 驱动补丁只存在于内存，**每次重启系统后都需要重新运行一次本工具**（证书与 `.sig` 无需重新生成，但重新运行会一并刷新）。

### 还原

点击 **还原签名** 可以：

- 把 `sbie_key_backup.bin` 里的原公钥写回驱动内存（需要驱动仍在运行，且能解析物理地址）
- 将 `*.sig.bak` 恢复为 `*.sig`
- 移除 `Certificate.dat`
- 停止并删除临时 `RTCore64` 服务

## 生成文件

程序会在当前目录生成以下文件：

| 文件 | 说明 |
|---|---|
| `Certificate.dat` | 生成的 Sandboxie-Plus 证书（同时自动复制到安装目录） |
| `key.hex` | 用于签发证书的私钥 |
| `mypub.hex` | 证书使用的公钥 |
| `sbie_key_backup.bin` | 驱动原始公钥备份（72 字节） |

请妥善保管 `key.hex` 和 `sbie_key_backup.bin`，并保留到所有改动完全还原为止。

## 故障排查

- **驱动加载失败：** 检查内存完整性、易受攻击驱动阻止列表或其他内核保护功能是否开启，并查看程序弹出的警告。
- **日志停在 `5/9 驱动映像中未找到 ECS1 公钥特征`：** 说明扫描的段里没有合法的 P-256 公钥 blob，通常是被安全软件拦了读取，或者驱动版本结构异常；把日志里的段表贴出来便于定位。
- **日志出现 `物理页已更新但虚拟地址读回仍是旧值`：** 物理写成功但 CPU 缓存未失效，重启系统后重新运行一次即可。
- **蓝屏风险：** 不要在卡巴斯基、360、火绒或其他低层级安全软件运行时使用本工具。
- **没有 UAC 提示：** 从资源管理器启动，或使用已提权的终端，并确认当前用户具有提权权限。
- **构建失败：** 确认已初始化 x64 MSVC 环境，并已安装 Windows SDK。

## 参与贡献

欢迎提交 Issue 和 Pull Request。修改代码时请保持 UI 与核心逻辑分离，并在提交前确认 Release 构建可以通过。