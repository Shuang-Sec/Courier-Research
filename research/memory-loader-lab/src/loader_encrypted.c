#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "MemoryModule.h"

// 文件作用：加密 bin 内存加载器。它读取 hello_payload.x64.bin，先用简单 XOR 解密出 DLL 原始字节，
// 再用 MemoryLoadLibrary 在内存中加载并调用导出函数。
// 这是学习“loader + 加密 bin”的最小闭环，不涉及真实 agent。

typedef int (__stdcall *HelloPayloadFn)(const char* outputPath);
typedef int (__stdcall *AddNumbersFn)(int a, int b);

// read_file：把 XOR 打包后的 hello_payload.x64.bin 读入内存。
// 此时读出来的还不是可加载 DLL，需要下一步 xor_crypt 还原。
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

// xor_crypt：循环使用 key 对 buffer 做 XOR。
// 因为 XOR 两次会还原，所以构建阶段 XOR 一次、运行阶段再 XOR 一次即可恢复 DLL。
static void xor_crypt(unsigned char* buf, size_t size, const char* key)
{
    size_t keyLen = strlen(key);
    if (!keyLen) return;
    for (size_t i = 0; i < size; i++) {
        buf[i] ^= (unsigned char)key[i % keyLen];
    }
}

// main：加密 bin 内存加载实验入口。
// 流程是：读 bin -> XOR 解密 -> 检查 MZ -> MemoryLoadLibrary ->
// 查找 HelloPayload/AddNumbers -> 调用并验证。
int main(int argc, char** argv)
{
    const char* binPath = argc > 1 ? argv[1] : "hello_payload.x64.bin";
    const char* outPath = argc > 2 ? argv[2] : "C:\\Users\\Public\\memory_loader_lab\\encrypted_loader_result.txt";
    const char* key = argc > 3 ? argv[3] : "ctf-memory-loader-key-20260624";
    unsigned char* payload = NULL;
    size_t payloadSize = 0;

    printf("LOADER=encrypted-xor\n");
    printf("BIN_PATH=%s\n", binPath);
    printf("OUT_PATH=%s\n", outPath);

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

    HelloPayloadFn hello = (HelloPayloadFn)MemoryGetProcAddress(module, "HelloPayload");
    AddNumbersFn add = (AddNumbersFn)MemoryGetProcAddress(module, "AddNumbers");
    printf("GETPROC_HelloPayload=%s\n", hello ? "OK" : "ERROR");
    printf("GETPROC_AddNumbers=%s\n", add ? "OK" : "ERROR");

    int helloRc = hello ? hello(outPath) : -1;
    int addRc = add ? add(13, 29) : -1;
    printf("HELLO_RC=%d\n", helloRc);
    printf("ADD_RC=%d\n", addRc);

    MemoryFreeLibrary(module);
    free(payload);
    printf("DONE=1\n");
    return (helloRc == 1337 && addRc == 42) ? 0 : 40;
}
