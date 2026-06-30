#include <windows.h>

// 文件作用：一个最小 DLL payload，用来学习“DLL 被从内存加载后如何调用导出函数”。
// 它不做 C2、不联网，只向指定路径写一行文本，方便确认导出函数确实被执行。

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpReserved;
    return TRUE;
}

// HelloPayload 是 loader 通过 MemoryGetProcAddress 找到并调用的导出函数。
// 参数 outputPath 是输出文件路径；函数写入一行证明自身运行过的文本，成功返回 1337。
__declspec(dllexport) int __stdcall HelloPayload(const char* outputPath)
{
    if (!outputPath || !outputPath[0]) {
        return 1001;
    }

    CHAR computer[128] = {0};
    DWORD computerLen = sizeof(computer);
    GetComputerNameA(computer, &computerLen);

    CHAR line[512] = {0};
    wsprintfA(line,
              "HELLO_PAYLOAD_OK computer=%s tick=%lu\r\n",
              computer,
              GetTickCount());

    HANDLE h = CreateFileA(outputPath,
                           GENERIC_WRITE,
                           FILE_SHARE_READ,
                           NULL,
                           CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return 1002;
    }

    DWORD written = 0;
    BOOL ok = WriteFile(h, line, lstrlenA(line), &written, NULL);
    CloseHandle(h);
    return ok ? 1337 : 1003;
}

// AddNumbers 是第二个导出函数，用来确认 MemoryGetProcAddress 可以正常找普通计算函数。
__declspec(dllexport) int __stdcall AddNumbers(int a, int b)
{
    return a + b;
}
