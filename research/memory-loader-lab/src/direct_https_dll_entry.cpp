// 文件作用：direct_https_agent 的 DLL 测试入口。
//
// 原来的 direct_https_agent 是 exe：Windows 从 WinMain/main 进入 AgentMain()。
// 内存加载实验需要 DLL 形式，所以这里额外导出 RunAgentDll()：
// loader 用 MemoryGetProcAddress("RunAgentDll") 找到它，再调用它。
//
// 这个文件本身不实现 agent 功能，只是把 DLL 导出函数转发到已有的 AgentMain()。
// 当前 full API 版本已经不只是 sleep-only probe：loader 会通过这个入口进入完整
// direct_https AgentMain，然后由 AgentMain 完成 ApiLoad、profile 初始化、网络回连、
// Commander 命令处理等逻辑。

#include <windows.h>
#include "main.h"

extern "C" __declspec(dllexport) DWORD WINAPI RunAgentDll(void)
{
    /*
     * 这是 loader 真正调用的入口。
     *
     * 为什么不直接从 DllMain 里启动 agent？
     * - DllMain 运行在 Windows loader lock 相关上下文中，不适合做复杂逻辑、
     *   网络连接、创建线程/进程等操作；
     * - 显式导出 RunAgentDll 后，loader 可以先确认 DLL 加载成功、导出函数存在，
     *   再由普通函数上下文进入 AgentMain。
     */
    return AgentMain(NULL);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    /*
     * DllMain 保持最小化：只返回 TRUE，不做网络、不做文件、不做复杂初始化。
     *
     * direct_https 的真正初始化全部放在 RunAgentDll -> AgentMain 中完成。
     */
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}
