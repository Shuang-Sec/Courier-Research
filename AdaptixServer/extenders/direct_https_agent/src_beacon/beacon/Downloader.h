// 文件作用：下载任务结构声明：保存每个下载任务的文件句柄、大小、偏移和状态。
#pragma once

#include "std.cpp"
#include "Packer.h"

#define COMMAND_DOWNLOAD  32
#define COMMAND_DOWNLOAD_STATE     35

#define DOWNLOAD_START    0x1
#define DOWNLOAD_CONTINUE 0x2
#define DOWNLOAD_FINISH   0x3

#define DOWNLOAD_STATE_RUNNING  0x1
#define DOWNLOAD_STATE_STOPPED  0x2
#define DOWNLOAD_STATE_FINISHED 0x3
#define DOWNLOAD_STATE_CANCELED 0x4

// DownloadData 保存一个文件下载任务的状态。
struct DownloadData {
	ULONG   taskId;
	ULONG   fileId;
	HANDLE  hFile;
	ULONG64 fileSize;
	ULONG64 index;
	BYTE    state;
};

// Downloader 管理所有正在进行的下载任务。
class Downloader
{
public:
	Vector<DownloadData> downloads;
	ULONG chunkSize = 0;

	// 构造函数设置每块下载大小。
	Downloader( ULONG chunk_size );

	// CreateDownloadData 新建下载任务记录。
	DownloadData CreateDownloadData(ULONG taskId, HANDLE hFile, ULONG64 size);
	// ProcessDownloader 每轮处理一个下载分片。
	void         ProcessDownloader(Packer* packer);
	// IsTasks 判断是否还有下载任务。
	BOOL		 IsTasks();

	// operator new 走自定义内存分配。
	static void* operator new(size_t sz);
	// operator delete 走自定义内存释放。
	static void operator delete(void* p) noexcept;
};