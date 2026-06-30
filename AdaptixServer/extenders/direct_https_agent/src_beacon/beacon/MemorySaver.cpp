// 文件作用：内存分片缓存实现：保存服务端下发的多片内存数据，并在收齐后交给任务使用。
#include "MemorySaver.h"

// MemorySaver::operator new 使用本项目的内存分配函数创建内存缓存器。
void* MemorySaver::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

// MemorySaver::operator delete 释放内存缓存器占用的本地内存。
void MemorySaver::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(MemorySaver));
}

// MemorySaver 构造函数初始化内存分片列表。
MemorySaver::MemorySaver(){}

// WriteMemoryData 保存一片内存数据；如果同 id 已存在就追加。
void MemorySaver::WriteMemoryData(ULONG memoryId, ULONG totalSize, ULONG dataSize, PBYTE data)
{
	if ( !chunks.contains(memoryId) ) {
		MemoryData memoryData = { 0 };
		memoryData.memoryId  = memoryId;
		memoryData.totalSize = totalSize;
		memoryData.buffer    = (PBYTE) MemAllocLocal(totalSize);
		
		chunks[memoryId] = memoryData;
	}

	memcpy( chunks[memoryId].buffer + chunks[memoryId].currentSize, data, dataSize );
	chunks[memoryId].currentSize += dataSize;

	if (chunks[memoryId].currentSize == chunks[memoryId].totalSize)
		chunks[memoryId].complete = true;
}

// RemoveMemoryData 根据 memory id 删除缓存的内存分片。
void MemorySaver::RemoveMemoryData(ULONG memoryId)
{
	if (chunks[memoryId].buffer)
		MemFreeLocal((LPVOID*)(&chunks[memoryId].buffer), chunks[memoryId].totalSize);
	chunks[memoryId] = { 0 };
	chunks.remove(memoryId);
}