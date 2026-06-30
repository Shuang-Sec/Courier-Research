// 文件作用：Windows 主机信息采集实现：读取用户名、主机名、进程名、系统版本、权限和内网 IP。
#include "ApiLoader.h"
#include "AgentInfo.h"
#include "utils.h"

// AgentInfo::operator new 使用本项目的内存分配函数创建主机信息对象。
void* AgentInfo::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

// AgentInfo::operator delete 释放主机信息对象占用的本地内存。
void AgentInfo::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(AgentInfo));
}

#if DIRECT_HTTPS_MINIMAL_IDENTITY

// AgentInfoString 安全复制字符串；如果来源为空，就返回 unknown。
static CHAR* AgentInfoString(const CHAR* value)
{
	DWORD length = 0;
	while (value[length] != 0)
		length++;

	CHAR* out = (CHAR*) MemAllocLocal(length + 1);
	if (!out)
		return NULL;

	memcpy(out, value, length);
	out[length] = 0;
	return out;
}

// AgentInfo 构造函数采集当前机器、用户、进程、系统版本、权限和内网 IP。
AgentInfo::AgentInfo()
{
	this->agent_id      = GenerateRandom32();
	this->acp           = 0;
	this->oemcp         = 0;
	this->gmt_offest    = 0;
	this->pid           = 0;
	this->tid           = 0;
	this->elevated      = FALSE;
	this->arch64        = (sizeof(void*) != 4);
	this->sys64         = this->arch64;
	this->build_number  = 0;
	this->major_version = 10;
	this->minor_version = 0;
	this->is_server     = FALSE;
	this->internal_ip   = 0;
	this->username      = AgentInfoString("lab-user");
	this->domain_name   = AgentInfoString("local");
	this->computer_name = AgentInfoString("win-lab");
	this->process_name  = AgentInfoString("agent.exe");
}

#else

// AgentInfo 构造函数在完整模式下调用 Windows API 采集真实主机信息。
AgentInfo::AgentInfo()
{
	SYSTEM_PROCESSOR_INFORMATION SystemInfo = { 0 };
	OSVERSIONINFOEXW OSVersion = { 0 };
	OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

	ApiNt->NtQuerySystemInformation(SystemProcessorInformation, &SystemInfo, sizeof(SYSTEM_PROCESSOR_INFORMATION), 0);
	ApiNt->RtlGetVersion((PRTL_OSVERSIONINFOW) &OSVersion);

	BOOL isWow64 = FALSE;
	ApiWin->IsWow64Process((HANDLE)-1, &isWow64);

	this->agent_id      = GenerateRandom32();
	this->acp           = ApiWin->GetACP();
	this->oemcp         = ApiWin->GetOEMCP();
	this->gmt_offest    = GetGmtOffset();
	this->pid           = (WORD)(ULONG_PTR) NtCurrentTeb()->ClientId.UniqueProcess;
	this->tid           = (WORD)(ULONG_PTR) NtCurrentTeb()->ClientId.UniqueThread;
	this->elevated      = IsElevate();
	this->arch64        = (sizeof(void*) != 4);
	this->sys64         = this->arch64 || isWow64;
	this->build_number  = OSVersion.dwBuildNumber;
	this->major_version = OSVersion.dwMajorVersion;
	this->minor_version = OSVersion.dwMinorVersion;
	this->is_server     = OSVersion.wProductType != VER_NT_WORKSTATION;
	this->internal_ip   = GetInternalIpLong();
	this->username      = _GetUserName();
	this->domain_name   = _GetDomainName();
	this->computer_name = _GetHostName();
	this->process_name  = _GetProcessName();
}

#endif
