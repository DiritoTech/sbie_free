// core.cpp — SandBoxie Unlocker 核心逻辑实现
// ========================================================================
// 证书生成 / 驱动服务管理 / SbieDrv.sys 公钥补丁 / .sig 重签 / 还原。
// 所有日志经 sbu::Log（回调）输出 UTF-8 单行文本，与 UI 解耦。
//
// 关于公钥补丁的实现差异（Sandboxie 1.18 vs 1.19）：
//   * 1.18.x 及更早：`static UCHAR KphpTrustedPublicKey[]` 位于可写的 .data 段，
//     直接用 RTCore64 的“内核虚拟地址写”原语即可打补丁。
//   * 1.19.x 起：该数组被加上 const（官方防止运行期篡改），编译器把它放进只读的
//     .rdata 段。继续按虚拟地址写会触发内核页错误（BSOD 0x50/0xBE），所以改为：
//       1) 扫描内存镜像的**全部**段定位 "ECS1"+0x20 特征（包含 .rdata）；
//       2) 读 ntoskrnl!PsInitialSystemProcess -> _EPROCESS.DirectoryTableBase 取得 CR3；
//       3) 走页表把公钥 VA 翻译成物理地址；
//       4) 用驱动的 MmMapIoSpace 映射该物理页后写入新公钥——物理写不受页表写保护限制。
// ========================================================================

#include "core.h"

#include <windows.h>
#include <psapi.h>
#include <bcrypt.h>
#include <cstdarg>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <ctime>
#include <algorithm>
#include <fstream>
#include <stdexcept>

#include "rtcore.h"
#include "sbie_api.h"
#include "windows_security_check.h"

namespace sbu {

// ---------------- 常量 ----------------
static const char* SOFTWARE_NAME = "Sandboxie-Plus";

// BCRYPT_ECCPUBLIC_BLOB: "ECS1" + cbKey(0x20) + X(32) + Y(32) = 72 字节
static const uint32_t kEcPublicMagic  = 0x31534345; // "ECS1" 小端
static const uint32_t kEcPublicCbKey  = 0x20;       // P-256
static const size_t   kPublicKeySize  = 72;

// ---------------- 日志（回调，UTF-8 单行） ----------------
static LogFn g_log = nullptr;

void SetLogger(LogFn fn) { g_log = fn; }

static void Log(const char* fmt, ...)
{
    if (!g_log) return;
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    g_log(buf);
}

// ---------------- 工具函数 ----------------
static void ThrowIf(NTSTATUS st, const char* what) {
    if (st != 0) throw std::runtime_error(std::string(what) + " (0x" +
        [&]{ char b[16]; snprintf(b, sizeof(b), "%08X", (unsigned)st); return std::string(b); }() + ")");
}

static std::string ToUpper(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::toupper);
    return r;
}

static std::string Hex(const std::vector<BYTE>& d) {
    static const char* h = "0123456789ABCDEF";
    std::string r; r.reserve(d.size() * 2);
    for (BYTE b : d) { r += h[b >> 4]; r += h[b & 0xF]; }
    return r;
}

static std::vector<BYTE> Sha256(const std::vector<BYTE>& data) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_HASH_HANDLE hHash = NULL;
    ThrowIf(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0), "SHA256 open");
    DWORD cbHash = 0, cbData = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(cbHash), &cbData, 0);
    std::vector<BYTE> hash(cbHash);
    ThrowIf(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0), "SHA256 create");
    if (!data.empty())
        ThrowIf(BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0), "SHA256 hash");
    ThrowIf(BCryptFinishHash(hHash, hash.data(), cbHash, 0), "SHA256 finish");
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

static std::string Base64Encode(const std::vector<BYTE>& data) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        unsigned n = (unsigned)data[i] << 16;
        if (i + 1 < data.size()) n |= (unsigned)data[i + 1] << 8;
        if (i + 2 < data.size()) n |= (unsigned)data[i + 2];
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += (i + 1 < data.size()) ? tbl[(n >> 6) & 63] : '=';
        out += (i + 2 < data.size()) ? tbl[n & 63] : '=';
    }
    return out;
}

static bool SaveRawFile(const char* path, const BYTE* data, size_t len)
{
    FILE* f = fopen(path, "wb");
    if (!f) return false;
    size_t w = fwrite(data, 1, len, f);
    fclose(f);
    return w == len;
}

static bool LoadRawFile(const char* path, std::vector<BYTE>& out)
{
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return !out.empty();
}

// ---------------- 密钥生成 / 签名 (CNG) ----------------
static void GenerateKeyPair(std::vector<BYTE>& privBlob, std::vector<BYTE>& pubBlob) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    ThrowIf(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0), "keygen open");
    ThrowIf(BCryptGenerateKeyPair(hAlg, &hKey, 256, 0), "keygen gen");
    ThrowIf(BCryptFinalizeKeyPair(hKey, 0), "keygen finalize");

    DWORD cb = 0;
    BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &cb, 0);
    privBlob.resize(cb);
    ThrowIf(BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB, privBlob.data(), cb, &cb, 0), "keygen export priv");
    BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cb, 0);
    pubBlob.resize(cb);
    ThrowIf(BCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pubBlob.data(), cb, &cb, 0), "keygen export pub");

    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
}

static std::vector<BYTE> SignDigest(const std::vector<BYTE>& privBlob, const std::vector<BYTE>& digest) {
    BCRYPT_ALG_HANDLE hAlg = NULL; BCRYPT_KEY_HANDLE hKey = NULL;
    ThrowIf(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0), "sign open");
    ThrowIf(BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB, &hKey,
        (PUCHAR)privBlob.data(), (ULONG)privBlob.size(), 0), "sign import");
    DWORD cbSig = 0;
    ThrowIf(BCryptSignHash(hKey, NULL, (PUCHAR)digest.data(), (ULONG)digest.size(), NULL, 0, &cbSig, 0), "sign size");
    std::vector<BYTE> sig(cbSig);
    ThrowIf(BCryptSignHash(hKey, NULL, (PUCHAR)digest.data(), (ULONG)digest.size(), sig.data(), cbSig, &cbSig, 0), "sign");
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    return sig;
}

// ---------------- 本机 SMBIOS UUID（与驱动 InitFwUuid 一致） ----------------
static std::string GetLocalUUID() {
    UINT size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (size == 0) return "";
    std::vector<BYTE> buf(size);
    if (GetSystemFirmwareTable('RSMB', 0, buf.data(), size) == 0) return "";
    if (buf.size() < 8) return "";

    BYTE* p = buf.data() + 8;
    BYTE* end = buf.data() + size;

    while (p + 4 <= end) {
        BYTE type = p[0];
        BYTE len = p[1];
        if (len < 4) break;
        if (type == 1 && len >= 0x19) {
            BYTE* raw = p + 8;
            bool allZero = true, allOne = true;
            for (int i = 0; i < 16; i++) {
                if (raw[i] != 0x00) allZero = false;
                if (raw[i] != 0xFF) allOne = false;
            }
            if (allZero || allOne) break;

            BYTE u[16];
            u[0]=raw[3]; u[1]=raw[2]; u[2]=raw[1]; u[3]=raw[0];
            u[4]=raw[5]; u[5]=raw[4];
            u[6]=raw[7]; u[7]=raw[6];
            for (int i = 8; i < 16; i++) u[i] = raw[i];

            char b[64];
            sprintf_s(b, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                u[0],u[1],u[2],u[3], u[4],u[5], u[6],u[7], u[8],u[9], u[10],u[11],u[12],u[13],u[14],u[15]);
            return b;
        }
        p += len;
        while (p + 1 < end && !(p[0] == 0 && p[1] == 0)) p++;
        p += 2;
    }
    return "";
}

// ---------------- 证书生成（固定 PERSONAL-<level>，HWID 节点锁定） ----------------
static std::vector<std::string> OptionsForLevel(const std::string& lv) {
    std::string u = ToUpper(lv);
    if (u == "HUGE" || u == "MAX" || u == "ETERNAL") return { "SBOX", "EBOX", "NETI", "DESK" };
    if (u == "ADVANCED")  return { "SBOX", "EBOX", "NETI" };
    if (u == "ADVANCED1") return { "SBOX", "EBOX" };
    return { "SBOX" }; // STANDARD / STANDARD2 / 其它
}

static std::string BuildCertificate(const std::string& name, const std::string& level,
                                    long long days, const std::string& hwid,
                                    const std::vector<BYTE>& privBlob, bool bom)
{
    std::vector<std::string> lines;
    lines.push_back("NAME: " + name);

    time_t now = time(nullptr); std::tm t; gmtime_s(&t, &now);
    char dbuf[64];
    snprintf(dbuf, sizeof(dbuf), "%02d.%02d.%04d+%lld", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, days);
    lines.push_back("DATE: " + std::string(dbuf));

    lines.push_back("TYPE: PERSONAL-" + ToUpper(level));

    auto options = OptionsForLevel(level);
    if (!options.empty()) {
        std::string o;
        for (size_t i = 0; i < options.size(); i++) { if (i) o += ", "; o += options[i]; }
        lines.push_back("OPTIONS: " + o);
    }
    lines.push_back("HWID: " + hwid);
    lines.push_back("SOFTWARE: " + std::string(SOFTWARE_NAME));

    // 哈希（SIGNATURE 不参与）
    std::vector<BYTE> input;
    for (auto& ln : lines) {
        size_t pos = ln.find(':');
        std::string nm = ln.substr(0, pos); while (!nm.empty() && (nm.back()==' '||nm.back()=='\t')) nm.pop_back();
        std::string vl = ln.substr(pos + 1); size_t s=vl.find_first_not_of(" \t"); if (s!=std::string::npos) vl = vl.substr(s); else vl="";
        input.insert(input.end(), nm.begin(), nm.end());
        input.insert(input.end(), vl.begin(), vl.end());
    }
    std::vector<BYTE> digest = Sha256(input);
    std::vector<BYTE> sig = SignDigest(privBlob, digest);

    std::string text;
    for (auto& ln : lines) text += ln + "\r\n";
    text += "SIGNATURE: " + Base64Encode(sig) + "\r\n";
    if (bom) text = "\xEF\xBB\xBF" + text;
    return text;
}

// ---------------- 模块基址 / PE 段表 ----------------
static uint64_t GetDriverBase(const char* name)
{
    LPVOID drivers[1024];
    DWORD cb = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) return 0;
    int n = (int)(cb / sizeof(LPVOID));
    char buf[MAX_PATH];
    for (int i = 0; i < n; i++) {
        if (!drivers[i]) continue;
        if (GetDeviceDriverBaseNameA(drivers[i], buf, sizeof(buf)) && _stricmp(buf, name) == 0)
            return (uint64_t)drivers[i];
    }
    return 0;
}

struct SectionInfo {
    std::string name;
    uint64_t    va;
    uint64_t    size;
    DWORD       chars;
};

static bool ReadSectionTable(const rtcore::RTCore& drv, uint64_t baseVa,
                             std::vector<SectionInfo>& out, bool verbose)
{
    BYTE hdr[0x800];
    try { drv.read_va(baseVa, hdr, sizeof(hdr)); }
    catch (const std::exception& e) { Log("    [!] 读取 PE 头失败: %s", e.what()); return false; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        Log("    [!] MZ 签名不匹配: e_magic=0x%04X (期望 0x5A4D)", dos->e_magic);
        return false;
    }
    if (dos->e_lfanew < 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(hdr)) {
        Log("    [!] e_lfanew 越界: 0x%08X", dos->e_lfanew);
        return false;
    }
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        Log("    [!] PE 签名不匹配: e_lfanew=0x%08X, Sig=0x%08X", dos->e_lfanew, nt->Signature);
        return false;
    }

    WORD numSections = nt->FileHeader.NumberOfSections;
    DWORD optHdrSize = nt->FileHeader.SizeOfOptionalHeader;
    BYTE* secStart = hdr + dos->e_lfanew + 4 + 20 + optHdrSize;
    if (secStart + (size_t)numSections * sizeof(IMAGE_SECTION_HEADER) > hdr + sizeof(hdr)) {
        Log("    [!] 段表超出 PE 头缓冲区 (%d 个段)", numSections);
        return false;
    }
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)secStart;

    if (verbose) Log("    段表 (%d 个):", numSections);
    out.clear();
    out.reserve(numSections);
    for (WORD i = 0; i < numSections; i++) {
        char name[9] = { 0 };
        memcpy(name, sec[i].Name, 8);
        SectionInfo si;
        si.name  = name;
        si.va    = baseVa + sec[i].VirtualAddress;
        si.size  = sec[i].Misc.VirtualSize;
        si.chars = sec[i].Characteristics;
        if (verbose)
            Log("      [%d] %-8s VA=+0x%05X 大小=0x%05X 属性=0x%08X%s",
                i, name, sec[i].VirtualAddress, sec[i].Misc.VirtualSize, si.chars,
                (si.chars & IMAGE_SCN_MEM_WRITE) ? " (可写)" : " (只读)");
        if (si.size == 0)
            si.size = sec[i].SizeOfRawData;
        out.push_back(si);
    }
    return true;
}

// 校验一段数据是不是合法的 P-256 公钥 blob（X/Y 必须在曲线上），用于排除误报
static bool IsValidEcPublicKey(const BYTE* blob, size_t len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (st != 0) return true; // 无法校验时放行，避免误伤
    st = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, (PUCHAR)blob, (ULONG)len, 0);
    if (hKey) BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return st == 0;
}

// 在一段里扫描 BCRYPT_ECCPUBLIC_BLOB 特征（"ECS1" + cbKey=0x20）
static bool ScanSectionForPublicKey(const rtcore::RTCore& drv, const SectionInfo& sec, uint64_t& outVa)
{
    const uint64_t end = sec.va + sec.size;
    for (uint64_t va = sec.va; va + kPublicKeySize <= end; va += 4) {
        if (((va - sec.va) & 0x1FFFF) == 0)
            Log("[.]       ...已扫描 0x%llX / 0x%llX", (unsigned long long)(va - sec.va), (unsigned long long)sec.size);

        uint32_t magic;
        try { magic = drv.read_u32(va); } catch (...) { return false; }
        if (magic != kEcPublicMagic) continue;

        uint32_t cbKey;
        try { cbKey = drv.read_u32(va + 4); } catch (...) { continue; }
        if (cbKey != kEcPublicCbKey) continue;

        // 排除全 0 的占位数据
        BYTE blob[kPublicKeySize] = { 0 };
        try { drv.read_va(va, blob, sizeof(blob)); } catch (...) { continue; }
        bool allZero = true;
        for (size_t i = 8; i < kPublicKeySize; i++) if (blob[i]) { allZero = false; break; }
        if (allZero) continue;

        // 曲线点校验：随机 64 字节几乎不可能落在 P-256 上，可有效排除误报
        if (!IsValidEcPublicKey(blob, sizeof(blob))) continue;

        outVa = va;
        return true;
    }
    return false;
}

// 在驱动镜像的所有段里定位公钥（1.19+ 位于只读的 .rdata）
static bool LocatePublicKey(const rtcore::RTCore& drv, uint64_t baseVa,
                            std::vector<SectionInfo>& secs,
                            uint64_t& keyVa, DWORD& keyChars)
{
    if (!ReadSectionTable(drv, baseVa, secs, true))
        return false;

    // 优先扫数据段（快），再退回扫其余段
    static const char* kPrefer[] = { ".rdata", ".data" };
    for (auto* want : kPrefer) {
        for (auto& s : secs) {
            if (_stricmp(s.name.c_str(), want) != 0 || s.size < kPublicKeySize) continue;
            Log("[.]     扫描段 %-8s (大小=0x%llX)...", s.name.c_str(), (unsigned long long)s.size);
            if (ScanSectionForPublicKey(drv, s, keyVa)) {
                keyChars = s.chars;
                Log("[+]     在 %s 段找到公钥", s.name.c_str());
                return true;
            }
        }
    }

    for (auto& s : secs) {
        if (s.size < kPublicKeySize) continue;
        if (_stricmp(s.name.c_str(), ".rdata") == 0 || _stricmp(s.name.c_str(), ".data") == 0) continue;
        Log("[.]     扫描段 %-8s (大小=0x%llX)...", s.name.c_str(), (unsigned long long)s.size);
        if (ScanSectionForPublicKey(drv, s, keyVa)) {
            keyChars = s.chars;
            Log("[+]     在 %s 段找到公钥", s.name.c_str());
            return true;
        }
    }
    return false;
}

// ---------------- 物理内存：读 / 写 ----------------
static uint64_t ReadPhys64(rtcore::RTCore& drv, uint64_t pa)
{
    BYTE buf[8] = { 0 };
    drv.read_phys(pa, buf, sizeof(buf)); // read_phys 内部按页 map/unmap，自动处理跨页
    uint64_t v = 0;
    memcpy(&v, buf, sizeof(v));
    return v;
}

// ---------------- ntoskrnl 导出 / CR3 / VA -> PA ----------------
static uint32_t FindExportRva(const rtcore::RTCore& drv, uint64_t imageBase, const char* target)
{
    BYTE hdr[0x800];
    try { drv.read_va(imageBase, hdr, sizeof(hdr)); } catch (...) { return 0; }

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew < 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(hdr)) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(hdr + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return 0;

    IMAGE_EXPORT_DIRECTORY ed = { 0 };
    try { drv.read_va(imageBase + dir.VirtualAddress, &ed, sizeof(ed)); } catch (...) { return 0; }
    if (!ed.NumberOfNames || !ed.AddressOfNames || !ed.AddressOfFunctions) return 0;

    const uint64_t names = imageBase + ed.AddressOfNames;
    const uint64_t ords  = imageBase + ed.AddressOfNameOrdinals;
    const uint64_t funcs = imageBase + ed.AddressOfFunctions;

    for (DWORD i = 0; i < ed.NumberOfNames; i++) {
        uint32_t nameRva = 0;
        try { drv.read_va(names + (uint64_t)i * 4, &nameRva, 4); } catch (...) { return 0; }

        char c = 0;
        try { drv.read_va(imageBase + nameRva, &c, 1); } catch (...) { continue; }
        if (c != target[0]) continue;

        char nm[48] = { 0 };
        try { drv.read_va(imageBase + nameRva, nm, sizeof(nm) - 1); } catch (...) { continue; }
        if (strcmp(nm, target) != 0) continue;

        WORD ord = 0;
        try { drv.read_va(ords + (uint64_t)i * 2, &ord, 2); } catch (...) { return 0; }
        if (ord >= ed.NumberOfFunctions) return 0;

        uint32_t fnRva = 0;
        try { drv.read_va(funcs + (uint64_t)ord * 4, &fnRva, 4); } catch (...) { return 0; }
        return fnRva;
    }
    return 0;
}

// Windows 内核态地址空间在所有进程里共享，取 System 进程的 CR3 即可翻译内核 VA
static bool GetSystemCr3(const rtcore::RTCore& drv, uint64_t& cr3)
{
    static const char* kNtNames[] = { "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe" };
    uint64_t ntBase = 0;
    for (auto* n : kNtNames) { ntBase = GetDriverBase(n); if (ntBase) break; }
    if (!ntBase) {
        Log("    [!] 未在已加载模块中找到 ntoskrnl.exe");
        return false;
    }

    uint32_t rva = FindExportRva(drv, ntBase, "PsInitialSystemProcess");
    if (!rva) {
        Log("    [!] ntoskrnl 导出表中未找到 PsInitialSystemProcess");
        return false;
    }

    uint64_t eprocess = drv.read_u64(ntBase + rva);
    if (!rtcore::is_kptr(eprocess)) {
        Log("    [!] PsInitialSystemProcess 指针无效: 0x%llX", (unsigned long long)eprocess);
        return false;
    }

    // _KPROCESS.DirectoryTableBase（x64 固定偏移 0x28）
    uint64_t dirBase = drv.read_u64(eprocess + 0x28);
    cr3 = dirBase & ~uint64_t(0xFFF);
    if (!cr3 || cr3 > 0x0000FFFFFFFFF000ULL) {
        Log("    [!] CR3 值异常: 0x%llX", (unsigned long long)cr3);
        return false;
    }
    Log("[+]     ntoskrnl=0x%llX SystemProcess=0x%llX CR3=0x%llX",
        (unsigned long long)ntBase, (unsigned long long)eprocess, (unsigned long long)cr3);
    return true;
}

static bool VaToPa(rtcore::RTCore& drv, uint64_t cr3, uint64_t va, uint64_t& pa)
{
    // PML4 -> PDPT
    uint64_t pml4e = ReadPhys64(drv, cr3 + 8 * ((va >> 39) & 0x1FF));
    if (!(pml4e & 1)) return false;

    uint64_t pdpte = ReadPhys64(drv, (pml4e & 0x000FFFFFFFFFF000ULL) + 8 * ((va >> 30) & 0x1FF));
    if (!(pdpte & 1)) return false;
    if (pdpte & 0x80) { // 1 GB 大页
        pa = (pdpte & 0x000FFFFFC0000000ULL) + (va & 0x3FFFFFFFULL);
        return true;
    }

    uint64_t pde = ReadPhys64(drv, (pdpte & 0x000FFFFFFFFFF000ULL) + 8 * ((va >> 21) & 0x1FF));
    if (!(pde & 1)) return false;
    if (pde & 0x80) { // 2 MB 大页
        pa = (pde & 0x000FFFFFFFE00000ULL) + (va & 0x1FFFFFULL);
        return true;
    }

    uint64_t pte = ReadPhys64(drv, (pde & 0x000FFFFFFFFFF000ULL) + 8 * ((va >> 12) & 0x1FF));
    if (!(pte & 1)) return false;

    pa = (pte & 0x000FFFFFFFFFF000ULL) + (va & 0xFFFULL);
    return true;
}

// ---------------- 驱动服务：检查 / 创建 / 启动 ----------------
static std::string FindDriverFile()
{
    char exe[MAX_PATH]; GetModuleFileNameA(NULL, exe, MAX_PATH);
    std::string dir = exe; dir = dir.substr(0, dir.find_last_of("\\/"));
    std::string cand = dir + "\\RTCore64.sys";
    if (GetFileAttributesA(cand.c_str()) != INVALID_FILE_ATTRIBUTES) return cand;
    return "";
}

static bool EnsureRtCoreDriver(bool& startedByUs)
{
    startedByUs = false;

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) { Log("[-] OpenSCManager 失败 (%lu)", GetLastError()); return false; }

    std::string ourDrvPath = FindDriverFile();
    if (ourDrvPath.empty()) { Log("[-] 未找到 RTCore64.sys"); CloseServiceHandle(hSCM); return false; }
    std::string ourNorm = ourDrvPath;
    std::transform(ourNorm.begin(), ourNorm.end(), ourNorm.begin(), ::tolower);

    SC_HANDLE hSvc = OpenServiceA(hSCM, "RTCore64", SERVICE_ALL_ACCESS);
    if (!hSvc) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            Log("[.] 服务不存在，从 %s 创建...", ourDrvPath.c_str());
            hSvc = CreateServiceA(hSCM, "RTCore64", "RTCore64", SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                ourDrvPath.c_str(), NULL, NULL, NULL, NULL, NULL);
            if (!hSvc) { Log("[-] CreateService 失败 (%lu)", GetLastError()); CloseServiceHandle(hSCM); return false; }
            startedByUs = true;
        } else {
            Log("[-] OpenService 失败 (%lu)", GetLastError());
            CloseServiceHandle(hSCM);
            return false;
        }
    } else {
        DWORD need = 0;
        QueryServiceConfigA(hSvc, NULL, 0, &need);
        std::vector<BYTE> cfgBuf(need > 0 ? need : 4096);
        LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)cfgBuf.data();
        if (QueryServiceConfigA(hSvc, cfg, (DWORD)cfgBuf.size(), &need) && cfg->lpBinaryPathName) {
            std::string existing = cfg->lpBinaryPathName;
            if (existing.rfind("\\??\\", 0) == 0) existing = existing.substr(4);
            std::string existingNorm = existing;
            std::transform(existingNorm.begin(), existingNorm.end(), existingNorm.begin(), ::tolower);
            if (existingNorm != ourNorm) {
                Log("[!] 已有 RTCore64 服务指向 %s（可能是 MSI Afterburner）", existing.c_str());
                Log("[.]     停止旧服务并改指向 %s...", ourDrvPath.c_str());
                SERVICE_STATUS st = { 0 };
                if (QueryServiceStatus(hSvc, &st) && st.dwCurrentState != SERVICE_STOPPED) {
                    ControlService(hSvc, SERVICE_CONTROL_STOP, &st);
                    for (int i = 0; i < 50; i++) {
                        Sleep(100);
                        if (QueryServiceStatus(hSvc, &st) && st.dwCurrentState == SERVICE_STOPPED) break;
                    }
                }
                if (!ChangeServiceConfigA(hSvc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                    ourDrvPath.c_str(), NULL, NULL, NULL, NULL, NULL, NULL)) {
                    Log("[-] ChangeServiceConfig 失败 (%lu)", GetLastError());
                    CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
                    return false;
                }
                Log("[+]     已将服务二进制路径改为我们的 RTCore64.sys");
            } else {
                Log("[+] 已有 RTCore64 服务指向相同文件，无需修改");
            }
        }
    }

    SERVICE_STATUS ss = { 0 };
    if (!QueryServiceStatus(hSvc, &ss)) {
        Log("[-] QueryServiceStatus 失败 (%lu)", GetLastError());
        CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
        return false;
    }
    if (ss.dwCurrentState == SERVICE_RUNNING) {
        Log("[+] RTCore64 服务已运行");
    } else {
        Log("[.] 启动 RTCore64 服务...");
        if (!StartServiceA(hSvc, 0, NULL)) {
            DWORD e = GetLastError();
            if (e != ERROR_SERVICE_ALREADY_RUNNING) {
                Log("[-] StartService 失败 (%lu)", e);
                CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
                return false;
            }
        }
        startedByUs = true;
        for (int i = 0; i < 30; i++) {
            Sleep(100);
            if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_RUNNING) break;
        }
        if (ss.dwCurrentState != SERVICE_RUNNING) {
            Log("[-] 服务未进入运行状态 (state=%lu)", ss.dwCurrentState);
            CloseServiceHandle(hSvc); CloseServiceHandle(hSCM);
            return false;
        }
        Log("[+] RTCore64 服务已启动");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return true;
}

static bool OpenRtCore(rtcore::RTCore& drv, bool& startedByUs)
{
    startedByUs = false;
    try { drv.open(); return true; } catch (...) {}

    Log("[.] RTCore64 驱动未运行，检查/创建/启动服务...");
    if (EnsureRtCoreDriver(startedByUs)) {
        try { drv.open(); return true; } catch (...) {}
    }
    return false;
}

static void StopAndDeleteRtCore()
{
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) { Log("[.] StopAndDeleteRtCore: OpenSCManager 失败 (%lu)", GetLastError()); return; }
    SC_HANDLE hSvc = OpenServiceA(hSCM, "RTCore64", SERVICE_ALL_ACCESS);
    if (!hSvc) { CloseServiceHandle(hSCM); return; }

    SERVICE_STATUS ss = { 0 };
    if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState != SERVICE_STOPPED) {
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 50; i++) {
            Sleep(100);
            if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) break;
        }
    }
    if (QueryServiceStatus(hSvc, &ss) && ss.dwCurrentState == SERVICE_STOPPED) {
        if (DeleteService(hSvc)) Log("[+] RTCore64 服务已停止并删除");
        else Log("[.] RTCore64 服务已停止但删除失败 (%lu)", GetLastError());
    } else {
        Log("[.] RTCore64 服务未能停止（可能有其他进程占用设备），跳过删除");
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
}

// ---------------- 兜底：直接写 .data 中的 Verify_CertInfo ----------------
// 1.19 起公钥被放进只读的 .rdata，正常路径必须做物理写；但有些机器的 HAL 不让
// 映射（A 报 0x1450、B 报 0x57），这条路就彻底断了。
//
// 此时退而写驱动**可写**的 .data 段：SCertInfo（Verify_CertInfo）就放在那里，
// 驱动在每次创建沙盒进程时都会读它，所以直接写成“满级永恒证书”即可解锁。
//
// 定位方式（不依赖硬编码地址）：
//   KphValidateCertificate 的第一句是 Verify_CertInfo.State = 0，会编译成
//   “mov qword ptr [rip+disp], 0”，把 .text 里所有这类指令的目标地址收出来
//   （它们都落在 .data），再用驱动 API 逐个验证：写进去能从 API 立刻读回来的就是它。
static const uint64_t kCertFullState =
      (1ULL << 0)     // active
    | (1ULL << 6)     // locked
    | (4ULL << 8)     // type  = eCertEternal
    | (7ULL << 13)    // level = eCertMaxLevel
    | (0xFULL << 28); // opt_desk | opt_net | opt_enc | opt_sec

static bool ReadSectionBytes(rtcore::RTCore& drv, const SectionInfo& s, std::vector<BYTE>& out)
{
    if (s.size == 0 || s.size > 0x400000)
        return false;
    out.assign((size_t)s.size, 0);
    for (size_t i = 0; i + 4 <= out.size(); i += 4) {
        uint32_t v;
        try { v = drv.read_u32(s.va + i); } catch (...) { return false; }
        memcpy(out.data() + i, &v, 4);
    }
    return true;
}

static std::vector<uint64_t> FindZeroStoreTargets(const std::vector<BYTE>& code, uint64_t codeVa,
                                                  uint64_t dataLo, uint64_t dataHi)
{
    std::vector<uint64_t> out;

    for (size_t i = 0; i + 11 <= code.size(); i++) {
        // 48 C7 05 disp32 imm32  ->  mov qword ptr [rip+disp32], imm32
        if (code[i] == 0x48 && code[i + 1] == 0xC7 && code[i + 2] == 0x05) {
            int32_t disp; uint32_t imm;
            memcpy(&disp, &code[i + 3], 4);
            memcpy(&imm, &code[i + 7], 4);
            if (imm == 0) {
                uint64_t t = codeVa + i + 11 + (int64_t)disp;
                if (t >= dataLo && t < dataHi) out.push_back(t);
            }
        }
        // C7 05 disp32 imm32      ->  mov dword ptr [rip+disp32], imm32
        if (i + 10 <= code.size() && code[i] == 0xC7 && code[i + 1] == 0x05) {
            int32_t disp; uint32_t imm;
            memcpy(&disp, &code[i + 2], 4);
            memcpy(&imm, &code[i + 6], 4);
            if (imm == 0) {
                uint64_t t = codeVa + i + 10 + (int64_t)disp;
                if (t >= dataLo && t < dataHi) out.push_back(t);
            }
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static bool PatchCertInfoFallback(rtcore::RTCore& drv, const std::vector<SectionInfo>& secs)
{
    SbieApi api;
    if (!api.open()) {
        Log("[-]     打不开 \\\\.\\SandboxieDriverApi（SbieSvc 没在运行？），兜底不可用");
        return false;
    }

    uint64_t before = 0;
    if (!api.query_cert_state(before)) {
        Log("[-]     驱动 API 查询证书状态失败，兜底不可用");
        return false;
    }
    Log("[.]     当前驱动证书状态: 0x%llX", (unsigned long long)before);

    const SectionInfo* text = nullptr;
    const SectionInfo* data = nullptr;
    for (auto& s : secs) {
        if (_stricmp(s.name.c_str(), ".text") == 0) text = &s;
        if (_stricmp(s.name.c_str(), ".data") == 0) data = &s;
    }
    if (!text || !data) {
        Log("[-]     段表里没有 .text/.data，兜底不可用");
        return false;
    }

    Log("[.]     读取 .text (0x%llX 字节) 以定位 Verify_CertInfo...", (unsigned long long)text->size);
    std::vector<BYTE> code;
    if (!ReadSectionBytes(drv, *text, code)) {
        Log("[-]     读取 .text 失败");
        return false;
    }

    auto cands = FindZeroStoreTargets(code, text->va, data->va, data->va + data->size);
    Log("[.]     找到 %zu 个候选地址，逐个用驱动 API 验证...", cands.size());
    if (cands.empty())
        return false;

    for (uint64_t addr : cands) {
        BYTE orig[8] = { 0 };
        try { drv.read_va(addr, orig, sizeof(orig)); } catch (...) { continue; }

        uint64_t origVal = 0;
        memcpy(&origVal, orig, 8);
        if (origVal != 0)          // 没有证书时这里应当是 0
            continue;

        try { drv.write_u64(addr, kCertFullState); } catch (...) { continue; }

        uint64_t st = 0;
        if (api.query_cert_state(st) && st == kCertFullState) {
            try { uint32_t zero = 0; drv.write_u32(addr + 8, zero); } catch (...) {}
            Log("[+]     命中 Verify_CertInfo: 0x%llX（写到 +0x8 的 expirers 也清零）",
                (unsigned long long)addr);
            uint64_t now = 0;
            if (api.query_cert_state(now))
                Log("[+]     驱动现在上报的证书状态: 0x%llX", (unsigned long long)now);
            return true;
        }

        try { drv.write_va(addr, orig, sizeof(orig)); } catch (...) {}  // 不是它，恢复
    }

    Log("[-]     候选地址都不是 Verify_CertInfo");
    return false;
}

// 探测可用的物理映射原语（这个驱动的两套映射在不同系统上表现不同）
static bool ProbeMapPrimitive(rtcore::RTCore& drv)
{
    static const char* kName1 = "A: HalTranslateBusAddress + MmMapIoSpace (0x80002040)";
    static const char* kName2 = "B: \\Device\\PhysicalMemory + ZwMapViewOfSection (0x80002000)";
    try {
        uint64_t va = drv.map_phys(0x100000, 0x1000); // 低端 1MB 必然是真 RAM
        drv.unmap_phys(va, 0x1000);
        Log("[+]     物理映射可用: %s", drv.map_method() == 1 ? kName1 : kName2);
        return true;
    } catch (const std::exception& e) {
        Log("[-]     物理映射不可用: %s", e.what());
        return false;
    }
}

// ---------------- 公钥补丁（核心） ----------------
// 把 newKey 写到 keyVa 指向的驱动内存：
//   可写的段  -> 直接虚拟地址写；
//   只读的段  -> 走 CR3 页表翻译出物理地址，map + 物理写（1.19+ 的 .rdata）。
static bool PatchPublicKey(rtcore::RTCore& drv, uint64_t keyVa, DWORD keyChars,
                           const std::vector<BYTE>& newKey)
{
    if (newKey.size() != kPublicKeySize) {
        Log("[-] 公钥长度异常: %zu", newKey.size());
        return false;
    }

    BYTE orig[kPublicKeySize] = { 0 };
    try { drv.read_va(keyVa, orig, sizeof(orig)); }
    catch (const std::exception& e) { Log("[-] 读取原公钥失败: %s", e.what()); return false; }

    if (GetFileAttributesA("sbie_key_backup.bin") == INVALID_FILE_ATTRIBUTES) {
        if (SaveRawFile("sbie_key_backup.bin", orig, sizeof(orig)))
            Log("[+]     原公钥已备份到 sbie_key_backup.bin");
        else
            Log("[-]     备份写入失败");
    } else {
        Log("[.]     备份文件已存在，跳过覆盖");
    }

    const bool writable = (keyChars & IMAGE_SCN_MEM_WRITE) != 0;

    // 只读段必须要物理映射，先自检一次，免得遍历页表时才炸
    bool mapOk = true;
    if (!writable)
        mapOk = ProbeMapPrimitive(drv);

    // 尝试拿到物理地址（只读段必须）
    uint64_t cr3 = 0, pa = 0;
    bool translated = false;
    if (!writable && !mapOk) {
        Log("[!]     跳过页表翻译（物理映射不可用）");
    } else {
        try {
            if (GetSystemCr3(drv, cr3) && VaToPa(drv, cr3, keyVa, pa)) {
                translated = true;
                Log("[+]     公钥物理地址: 0x%llX (页内偏移 0x%llX)",
                    (unsigned long long)pa, (unsigned long long)(pa & 0xFFF));
            }
        } catch (const std::exception& e) {
            Log("[!]     页表翻译异常: %s", e.what());
        }
    }

    auto writeKey = [&](const BYTE* data) -> bool {
        if (!translated) {
            if (!writable) return false;
            try {
                Log("[.]     未能翻译物理地址，退回可写段直接写入");
                drv.write_va(keyVa, data, kPublicKeySize);
                return true;
            } catch (const std::exception& e) {
                Log("[-]     写入失败: %s", e.what());
                return false;
            }
        }

        uint64_t mapVa = 0;
        try { mapVa = drv.map_phys(pa, 0x1000); }
        catch (const std::exception& e) { Log("[-]     映射公钥页失败: %s", e.what()); return false; }

        // 用"原公钥内容"校验映射是否正确（同时兜住 64KB 窗口偏移的解释差异）
        BYTE probe[kPublicKeySize] = { 0 };
        bool ok = false;
        try { drv.read_va(mapVa, probe, sizeof(probe)); ok = memcmp(probe, orig, sizeof(probe)) == 0; } catch (...) {}

        if (!ok && drv.map_method() == 2) {
            uint64_t alt = mapVa - (pa & 0xFFFF);
            try {
                drv.read_va(alt, probe, sizeof(probe));
                if (memcmp(probe, orig, sizeof(probe)) == 0) { ok = true; mapVa = alt; }
            } catch (...) {}
        }
        if (!ok) {
            Log("[-]     映射出来的内容与原公钥不符，放弃写入");
            drv.unmap_phys(mapVa, 0x1000);
            return false;
        }

        try { drv.write_va(mapVa, data, kPublicKeySize); }
        catch (const std::exception& e) {
            Log("[-]     写入失败: %s", e.what());
            drv.unmap_phys(mapVa, 0x1000);
            return false;
        }
        drv.unmap_phys(mapVa, 0x1000);
        return true;
    };

    if (!writeKey(newKey.data())) {
        if (!writable) {
            if (!mapOk)
                Log("[-]     公钥位于只读段，且两套物理映射原语都不可用，无法完成物理写");
            else
                Log("[-]     公钥位于只读段，但映射/翻译没能完成，无法确认写入");
            Log("         已尝试 A(MmMapIoSpace) 与 B(\\Device\\PhysicalMemory 64KB 窗口)");
        }
        return false;
    }

    // 校验：走原始 VA（CPU 缓存视图，和驱动看到的一致）
    auto verifyVa = [&]() -> bool {
        BYTE chk[kPublicKeySize] = { 0 };
        try { drv.read_va(keyVa, chk, sizeof(chk)); } catch (...) { return false; }
        return memcmp(chk, newKey.data(), kPublicKeySize) == 0;
    };

    if (verifyVa()) {
        Log("[+]     新公钥已写入，虚拟地址读回校验通过");
        return true;
    }

    Log("[!]     虚拟地址读回不一致，尝试二次写入...");
    if (!writeKey(newKey.data())) return false;
    if (verifyVa()) {
        Log("[+]     新公钥已写入，二次校验通过");
        return true;
    }

    Log("[-]     读回校验失败，回滚原公钥...");
    writeKey(orig);
    return false;
}

// ---------------- 重新签名可执行文件（生成 <exe>.sig） ----------------
static bool SignFile(const std::string& exePath, const std::vector<BYTE>& privBlob)
{
    std::ifstream ifs(exePath, std::ios::binary);
    if (!ifs) return false;
    std::vector<BYTE> content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    ifs.close();
    if (content.empty()) return false;

    std::vector<BYTE> digest = Sha256(content);
    std::vector<BYTE> sig = SignDigest(privBlob, digest); // 原始 R||S 64B

    std::string sigPath = exePath + ".sig";
    std::string bakPath = exePath + ".sig.bak";

    if (GetFileAttributesA(bakPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::ifstream isig(sigPath, std::ios::binary);
        if (isig.good()) {
            std::vector<BYTE> orig((std::istreambuf_iterator<char>(isig)), std::istreambuf_iterator<char>());
            isig.close();
            std::ofstream osig(bakPath, std::ios::binary);
            osig.write((const char*)orig.data(), (std::streamsize)orig.size());
        }
    }

    std::ofstream ofs(sigPath, std::ios::binary);
    ofs.write((const char*)sig.data(), (std::streamsize)sig.size());
    ofs.close();
    return true;
}

static const char* kSignTargets[] = { "SandMan.exe", "SbieCtrl.exe", "SbieSvc.exe", "Start.exe" };

static int ResignExecutables(const std::string& dir, const std::vector<BYTE>& privBlob)
{
    int n = 0;
    for (auto* t : kSignTargets) {
        std::string exe = dir + "\\" + t;
        if (GetFileAttributesA(exe.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        if (SignFile(exe, privBlob)) {
            Log("[+]     已重签: %s.sig", t);
            n++;
        }
    }
    return n;
}

// 从 SbieDrv 服务路径推断安装目录，失败则用默认路径
static std::string GetInstallDir()
{
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceA(hSCM, "SbieDrv", SERVICE_QUERY_CONFIG);
        if (hSvc) {
            DWORD need = 0;
            QueryServiceConfigA(hSvc, NULL, 0, &need);
            std::vector<BYTE> buf(need > 0 ? need : 4096);
            LPQUERY_SERVICE_CONFIGA cfg = (LPQUERY_SERVICE_CONFIGA)buf.data();
            if (QueryServiceConfigA(hSvc, cfg, (DWORD)buf.size(), &need) && cfg->lpBinaryPathName) {
                std::string p = cfg->lpBinaryPathName;
                if (p.rfind("\\??\\", 0) == 0) p = p.substr(4);
                size_t slash = p.find_last_of("\\/");
                if (slash != std::string::npos) p = p.substr(0, slash);
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSCM);
                return p;
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }
    return "C:\\Program Files\\Sandboxie-Plus";
}

// 把生成的 Certificate.dat 放进安装目录（驱动从 %安装目录%\Certificate.dat 读取）
static bool InstallCertificate(const std::string& installDir)
{
    std::string dst = installDir + "\\Certificate.dat";
    if (GetFileAttributesA("Certificate.dat") == INVALID_FILE_ATTRIBUTES) {
        Log("[-]     当前目录没有 Certificate.dat");
        return false;
    }
    if (!CopyFileA("Certificate.dat", dst.c_str(), FALSE)) {
        Log("[-]     复制 Certificate.dat 到 %s 失败 (%lu)", installDir.c_str(), GetLastError());
        return false;
    }
    Log("[+]     Certificate.dat 已放入安装目录");
    return true;
}

// ---------------- 一键流程 ----------------
// RAII：RunFlow 任何路径退出（包括提前 return）都停止并删除 RTCore64 服务。
// 仅当服务是我们创建/启动时才清理，避免影响 MSI Afterburner 等已有使用方。
struct SvcGuard {
    bool active = false;
    ~SvcGuard() { if (active) StopAndDeleteRtCore(); }
};

void RunFlow(const std::string& name, const std::string& level, long long days)
{
    Log("[*] 一键流程: name=\"%s\" level=%s days=%lld", name.c_str(), level.c_str(), days);

    // 1) HWID
    std::string hwid = GetLocalUUID();
    if (hwid.empty()) { Log("[-] 读取本机 SMBIOS UUID 失败"); return; }
    Log("[+] 1/9 本机 HWID: %s", hwid.c_str());

    // 2) 密钥对
    std::vector<BYTE> priv, pub;
    try { GenerateKeyPair(priv, pub); }
    catch (const std::exception& e) { Log("[-] 2/9 密钥生成失败: %s", e.what()); return; }
    Log("[+] 2/9 已生成 ECDSA P-256 密钥对");

    // 3) 证书
    std::string certText = BuildCertificate(name, level, days, hwid, priv, true);
    { std::ofstream ofs("Certificate.dat", std::ios::binary); ofs << certText; }
    { std::ofstream ofs("key.hex");  ofs << Hex(priv) << "\n"; }
    { std::ofstream ofs("mypub.hex"); ofs << Hex(pub) << "\n"; }
    Log("[+] 3/9 已生成 Certificate.dat / key.hex / mypub.hex");
    Log("    公钥: %s", Hex(pub).c_str());

    // 4) 打开驱动
    SvcGuard svcGuard;
    rtcore::RTCore drv;
    bool startedByUs = false;
    Log("[.] 内核保护状态: %s", DescribeKernelProtections().c_str());
    if (!OpenRtCore(drv, startedByUs)) {
        Log("[-] 4/9 无法打开 RTCore64 驱动，补丁跳过（证书已生成，可稍后手动补丁）");
        return;
    }
    svcGuard.active = startedByUs;
    Log("[+] 4/9 RTCore64 驱动已打开");

    // 5) 定位公钥（1.19+ 在只读的 .rdata）
    uint64_t baseVa = GetDriverBase("SbieDrv.sys");
    if (!baseVa) { Log("[-] 5/9 未找到 SbieDrv.sys，补丁跳过"); return; }
    Log("[+] 5/9 SbieDrv.sys 基址 VA: 0x%llX", (unsigned long long)baseVa);

    uint64_t keyVa = 0;
    DWORD keyChars = 0;
    std::vector<SectionInfo> secs;
    if (!LocatePublicKey(drv, baseVa, secs, keyVa, keyChars)) {
        Log("[-] 5/9 驱动映像中未找到 ECS1 公钥特征");
        return;
    }
    Log("[+]     公钥 VA=0x%llX 所在段属性=0x%08X%s",
        (unsigned long long)keyVa, keyChars, (keyChars & IMAGE_SCN_MEM_WRITE) ? " (可写)" : " (只读)");

    // 6) 备份 + 打补丁 + 校验
    if (!PatchPublicKey(drv, keyVa, keyChars, pub)) {
        Log("[!] 6/9 公钥补丁失败，改用 .data 兜底（直接写 Verify_CertInfo）...");
        if (!PatchCertInfoFallback(drv, secs)) {
            Log("[-] 6/9 兜底也失败，本次未能解锁");
            return;
        }
        Log("");
        Log("[+] 6/9 已通过驱动数据段解锁（没有改动只读段）");
        Log("    注意以下三点：");
        Log("    1) 这是内存补丁，重启系统后失效，重新运行本工具即可；");
        Log("    2) 重启 SandMan / 重装证书会让驱动重新校验并把状态清零，需要重新运行本工具；");
        Log("    3) SandMan 界面里仍显示“未认证”，新建盒子时的类型下拉可能仍受限，");
        Log("       但驱动层已经放行：已配置 SecurityMode/PrivacyMode/ConfidentialBox 等特性的");
        Log("       盒子可以正常工作（可直接编辑 Sandboxie.ini 或用模板设置）。");
        return;
    }
    Log("[+] 6/9 驱动公钥已替换");

    // 7) 重签 exe
    std::string installDir = GetInstallDir();
    if (GetFileAttributesA(installDir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        Log("[-] 7/9 未找到安装目录 %s，跳过重签", installDir.c_str());
    } else {
        int n = ResignExecutables(installDir, priv);
        Log("[+] 7/9 已重签 %d 个可执行文件（原 .sig 备份为 *.sig.bak）", n);
        if (n == 0)
            Log("[!]     未能重签任何可执行文件：SandMan/SbieSvc 将无法通过驱动校验，"
                "请检查安装目录写权限，必要时先执行 [还原签名]");
    }

    // 8) 放置证书
    if (GetFileAttributesA(installDir.c_str()) != INVALID_FILE_ATTRIBUTES)
        InstallCertificate(installDir);
    else
        Log("[-] 8/9 安装目录不存在，请手动把 Certificate.dat 放到 Sandboxie-Plus 目录");

    // 9) 完成
    Log("");
    Log("[+] 9/9 全部完成！");
    Log("    证书: Certificate.dat（节点锁定 %s）", hwid.c_str());
    Log("    安装目录: %s", installDir.c_str());
    Log("    请重启 Sandboxie-Plus（SandMan.exe）使其重新加载证书");
    Log("    注意: 内存补丁重启系统后失效，届时重新运行本工具即可");
}

// ---------------- 还原 ----------------
void RunRestore()
{
    Log("[*] 开始还原...");

    // 1) 尝试把驱动内存中的公钥还原（前提：驱动仍在运行）
    std::vector<BYTE> backup;
    if (!LoadRawFile("sbie_key_backup.bin", backup) || backup.size() != kPublicKeySize) {
        Log("[.] 未找到有效的 sbie_key_backup.bin，跳过驱动内存公钥还原");
    } else {
        // 先声明 SvcGuard，再声明 RTCore，保证析构时先关设备句柄再停服务
        SvcGuard svcGuard;
        rtcore::RTCore drv;
        bool startedByUs = false;
        if (OpenRtCore(drv, startedByUs)) {
            svcGuard.active = startedByUs;

            uint64_t baseVa = GetDriverBase("SbieDrv.sys");
            uint64_t keyVa = 0;
            DWORD keyChars = 0;
            std::vector<SectionInfo> secs;
            if (baseVa && LocatePublicKey(drv, baseVa, secs, keyVa, keyChars)) {
                uint64_t cr3 = 0, pa = 0;
                bool translated = false;
                try {
                    if (GetSystemCr3(drv, cr3) && VaToPa(drv, cr3, keyVa, pa))
                        translated = true;
                } catch (...) {}

                bool ok = false;
                try {
                    if (translated) {
                        drv.write_phys(pa, backup.data(), backup.size());
                        ok = true;
                    } else if (keyChars & IMAGE_SCN_MEM_WRITE) {
                        drv.write_va(keyVa, backup.data(), backup.size());
                        ok = true;
                    }
                } catch (const std::exception& e) {
                    Log("[-] 还原写入失败: %s", e.what());
                }

                if (ok) {
                    BYTE chk[kPublicKeySize] = { 0 };
                    try { drv.read_va(keyVa, chk, sizeof(chk)); } catch (...) {}
                    if (memcmp(chk, backup.data(), kPublicKeySize) == 0)
                        Log("[+] 驱动内存公钥已还原");
                    else
                        Log("[-] 驱动内存公钥读回校验失败");
                } else {
                    Log("[-] 驱动内存公钥还原失败");
                }
            } else {
                Log("[.] 未定位到驱动公钥，跳过内存还原");
            }
        } else {
            Log("[.] RTCore64 不可用，跳过驱动内存公钥还原");
        }
    }

    // 2) 还原 .sig
    std::string installDir = GetInstallDir();
    for (auto* t : kSignTargets) {
        std::string bak = installDir + "\\" + t + ".sig.bak";
        std::string sig = installDir + "\\" + t + ".sig";
        if (GetFileAttributesA(bak.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        std::ifstream ib(bak, std::ios::binary);
        if (ib.good()) {
            std::vector<BYTE> data((std::istreambuf_iterator<char>(ib)), std::istreambuf_iterator<char>());
            ib.close();
            std::ofstream os(sig, std::ios::binary);
            os.write((const char*)data.data(), (std::streamsize)data.size());
            os.close();
            Log("[+] 已还原 %s.sig", t);
        }
    }

    // 3) 删除证书
    std::string certIn = installDir + "\\Certificate.dat";
    if (GetFileAttributesA(certIn.c_str()) != INVALID_FILE_ATTRIBUTES) {
        DeleteFileA(certIn.c_str());
        Log("[+] 已移除安装目录的 Certificate.dat");
    }
    if (GetFileAttributesA("Certificate.dat") != INVALID_FILE_ATTRIBUTES) {
        DeleteFileA("Certificate.dat");
        Log("[+] 已移除当前目录的 Certificate.dat");
    }
    Log("[*] 还原完成。若驱动内存补丁仍存在，请重启系统以彻底恢复原公钥。");
}

} // namespace sbu
