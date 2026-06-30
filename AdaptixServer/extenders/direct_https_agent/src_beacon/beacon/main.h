// 文件作用：Windows agent 入口声明：暴露全局 agent 指针、AgentMain 和 AgentExit。
#pragma once

#include "Agent.h"

extern Agent* g_Agent;

// AgentMain 是 agent 主入口。
DWORD WINAPI AgentMain(LPVOID lpParam);

// AgentExit 根据配置退出线程或进程。
void AgentExit(int method);