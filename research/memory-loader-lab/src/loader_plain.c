#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "MemoryModule.h"

// 文件作用：明文 DLL 内存加载器。它从磁盘读取 hello_payload.dll 的原始字节，
// 用 MemoryLoadLibrary 从内存加载，然后调用 DLL 导出的 HelloPayload 和 AddNumbers。
// 这是学习用 baseline：先证明“内存加载 DLL”这件事能跑通。

typedef int (__stdcall *HelloPayloadFn)(const char* outputPath);
typedef int (__stdcall *AddNumbersFn)(int a, int b);

// read_file：把磁盘上的 DLL 文件一次性读到内存。
// 小白理解：后面的 MemoryLoadLibrary 需要的是“一整块 DLL 字节”，
// 所以这里先完成“文件路径 -> 内存 buffer”的转换。
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

// main：明文内存加载实验入口。
// 流程是：读取 hello_payload.x64.dll -> MemoryLoadLibrary 手动加载 ->
// MemoryGetProcAddress 找 HelloPayload/AddNumbers -> 调用函数并验证返回值。
int main(int argc, char** argv)
{
    const char* dllPath = argc > 1 ? argv[1] : "hello_payload.x64.dll";
    const char* outPath = argc > 2 ? argv[2] : "C:\\Users\\Public\\memory_loader_lab\\plain_loader_result.txt";
    unsigned char* dllBytes = NULL;
    size_t dllSize = 0;

    printf("LOADER=plain\n");
    printf("DLL_PATH=%s\n", dllPath);
    printf("OUT_PATH=%s\n", outPath);

    int rc = read_file(dllPath, &dllBytes, &dllSize);
    if (rc != 0) {
        printf("READ_DLL=ERROR:%d\n", rc);
        return 10 + rc;
    }
    printf("READ_DLL=OK size=%lu\n", (unsigned long)dllSize);

    HMEMORYMODULE module = MemoryLoadLibrary(dllBytes, dllSize);
    if (!module) {
        printf("MEMORY_LOAD=ERROR\n");
        free(dllBytes);
        return 20;
    }
    printf("MEMORY_LOAD=OK\n");

    HelloPayloadFn hello = (HelloPayloadFn)MemoryGetProcAddress(module, "HelloPayload");
    AddNumbersFn add = (AddNumbersFn)MemoryGetProcAddress(module, "AddNumbers");
    printf("GETPROC_HelloPayload=%s\n", hello ? "OK" : "ERROR");
    printf("GETPROC_AddNumbers=%s\n", add ? "OK" : "ERROR");

    int helloRc = hello ? hello(outPath) : -1;
    int addRc = add ? add(7, 35) : -1;
    printf("HELLO_RC=%d\n", helloRc);
    printf("ADD_RC=%d\n", addRc);

    MemoryFreeLibrary(module);
    free(dllBytes);
    printf("DONE=1\n");
    return (helloRc == 1337 && addRc == 42) ? 0 : 30;
}
