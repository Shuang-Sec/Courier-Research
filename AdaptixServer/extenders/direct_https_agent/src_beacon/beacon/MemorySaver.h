// 文件作用：内存分片缓存声明：定义内存块结构和写入/删除接口。
#pragma once

#include "std.cpp"
#include "Packer.h"

// MemoryData 保存一次上传/内存分片任务的缓存状态。
struct MemoryData {
	ULONG memoryId;
	ULONG totalSize;
	ULONG currentSize;
	PBYTE buffer;
	BOOL  complete;
};

// MemorySaver 负责保存和删除内存分片。
class MemorySaver
{
public:
	Map<ULONG, MemoryData> chunks;

	// 构造函数初始化缓存容器。
	MemorySaver();

	// WriteMemoryData 写入一个分片。
	void WriteMemoryData(ULONG memoryId, ULONG totalSize, ULONG dataSize, PBYTE data);
	// RemoveMemoryData 删除一个缓存记录。
	void RemoveMemoryData(ULONG memoryId);

	// operator new 走自定义内存分配。
	static void* operator new(size_t sz);
	// operator delete 走自定义内存释放。
	static void operator delete(void* p) noexcept;
};