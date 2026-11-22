# SandBoxie Unlocker

[![Build & Release](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml/badge.svg)](https://github.com/A11waysY0U/sbie_free/actions/workflows/build.yml)

A Windows GUI utility for creating a hardware-locked Sandboxie-Plus sponsor certificate and applying the corresponding in-memory driver patch.

**Language:** English | [简体中文](README_zh.md)

## Overview

SandBoxie Unlocker:

1. Reads the hardware identifier of the current machine.
2. Generates an ECC key pair and a node-locked `Certificate.dat`.
3. Loads `RTCore64.sys` and patches the in-memory public key used by `SbieDrv.sys`.
4. Re-signs the Sandboxie executable signature (`.sig`) so the patched driver accepts the generated certificate.
5. Places `Certificate.dat` in the Sandboxie installation directory.
6. Removes the temporary driver service when the operation finishes.

> **Research and educational use only.** The driver patch exists only in memory and disappears after a reboot. Modifying Windows security settings or loading a vulnerable kernel driver can destabilize the system and may cause a blue screen. Use this utility only on a test machine whose data you can afford to lose.

## Version compatibility

| Sandboxie-Plus | Public key location | Patch method |
|---|---|---|
| 1.18.x and older | writable `.data` (`static UCHAR`) | direct kernel virtual-address write |
| 1.19.x and newer | **read-only `.rdata`** (`static const UCHAR`, hardened against runtime tampering) | page-table translation to a physical address, then `MmMapIoSpace` + physical write |

Starting with 1.19 the upstream project declares `KphpTrustedPublicKey` as `const`, so the compiler places it in a read-only section. Writing it through a virtual address would fault in kernel mode (blue screen), so the tool now automatically:

1. scans **every** section of the mapped image for the `"ECS1" + 0x20` key blob (validated as a real P-256 point to rule out false positives);
2. reads `ntoskrnl!PsInitialSystemProcess` → `_EPROCESS.DirectoryTableBase` to obtain CR3;
3. walks the page tables to translate the key virtual address into a physical address;
4. maps that physical page through the driver's `MmMapIoSpace` and writes the new key there — a physical write is not affected by page write protection.

Both code paths are handled by the same build, no version switch is required.

## Safety checks

Before starting a registration, the application checks for:

- Memory integrity (HVCI)
- Microsoft's vulnerable-driver blocklist
- Kernel-mode hardware-enforced stack protection
- Known conflicting security software, including Kaspersky, 360, and Huorong processes

The application blocks the operation when one of these conditions is detected. If the process snapshot cannot be created, the current implementation continues because no conflicting process was found.

## Repository layout

```text
.
├── CMakeLists.txt
├── README.md
├── README_zh.md
├── src/
│   ├── core.cpp                    # Certificate generation, driver patching, signing, restore
│   ├── core.h
│   ├── main.cpp                    # Win32 GUI
│   ├── windows_security_check.cpp  # Driver compatibility and security software checks
│   └── windows_security_check.h
└── third_party/
    ├── rtcore.h                    # RTCore64 ioctl wrapper
    └── RTCore64.sys
```

## Requirements

- Windows x64
- Visual Studio 2022 or Build Tools 2022 with the MSVC toolchain and Windows SDK
- CMake 3.15 or newer
- `RTCore64.sys` in `third_party/`

CMake automatically copies `RTCore64.sys` next to the executable after a successful build.

## Build

### Visual Studio generator

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output:

```text
build\Release\SandBoxieUnlocker.exe
build\Release\RTCore64.sys
```

### Ninja generator

Initialize an x64 MSVC environment first. For example:

```powershell
cmd /c "call ""C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"" && cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build"
```

Output:

```text
build\SandBoxieUnlocker.exe
build\RTCore64.sys
```

If you use another Visual Studio edition, adjust the path to `vcvars64.bat` accordingly.

## Usage

1. Place `SandBoxieUnlocker.exe` and `RTCore64.sys` in the Sandboxie installation directory.
2. Run `SandBoxieUnlocker.exe` as an administrator. The application requests UAC elevation automatically when required.
3. Enter a name, select a level (`STANDARD`, `ADVANCED`, `ADVANCED1`, or `HUGE`), and specify the certificate validity period in days.
4. Select **Register**.
5. When the log shows `9/9` (all steps finished), restart Sandboxie-Plus. `Certificate.dat` is copied into the installation directory automatically.

> The driver patch lives only in memory, so **run the tool again after every reboot** (the certificate and `.sig` files stay valid, but re-running refreshes everything).

### Restore

Select **Restore signature** to:

- write the original public key from `sbie_key_backup.bin` back into the running driver (requires the driver to be loaded and the page translation to succeed)
- restore every `*.sig.bak` file to `*.sig`
- remove `Certificate.dat`
- stop and remove the temporary `RTCore64` service

## Generated files

The application writes the following files to its current directory:

| File | Description |
|---|---|
| `Certificate.dat` | Generated Sandboxie-Plus certificate (also copied into the installation directory) |
| `key.hex` | Private key used to sign the certificate |
| `mypub.hex` | Public key used by the certificate |
| `sbie_key_backup.bin` | Backup of the original driver public key (72 bytes) |

Keep `key.hex` and `sbie_key_backup.bin` private and retain them until all changes have been restored.

## Troubleshooting

- **Driver load failure:** Check whether memory integrity, vulnerable-driver blocking, or another kernel-protection feature is enabled. Review the warning shown by the application.
- **Log stops at `5/9` (key not found):** No valid P-256 key blob was found in the scanned sections — usually a security product blocking the reads, or an unexpected driver layout. Include the section table printed in the log when reporting.
- **`physical page updated but virtual-address read-back still shows the old value`:** the physical write succeeded but the CPU cache was not invalidated; reboot and run the tool again.
- **Blue-screen risk:** Do not run the utility while Kaspersky, 360, Huorong, or other low-level security software is active.
- **No UAC prompt:** Launch the executable from Explorer or use an elevated terminal, and verify that your user is allowed to elevate.
- **Build failure:** Confirm that the x64 MSVC environment is initialized and that the Windows SDK is installed.

## Contributing

Issues and pull requests are welcome. For code changes, please keep the UI and core logic separated and make sure the Release build passes before submitting.