// 文件作用：Windows 程序入口：把 exe 的 main/WinMain 入口转发到 AgentMain。
#include "main.h"
#include "config.h"

#if defined(DEBUG)

// main 是 DEBUG 控制台构建入口，方便本地调试时直接调用 AgentMain。
int main()
{
    return (int)AgentMain(NULL);
}

#else

// WinMain 是 Windows GUI 子系统入口，正常 exe 从这里进入 AgentMain。
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    return (int)AgentMain(NULL);
}

#endif
