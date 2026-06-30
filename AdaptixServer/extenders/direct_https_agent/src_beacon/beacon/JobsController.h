// 文件作用：后台 job 数据结构声明：保存进程类任务的句柄、PID、管道和状态。
#pragma once

#include "std.cpp"
#include "Packer.h"

#define COMMAND_JOB 0x8437

#define JOB_TYPE_PROCESS  0x3

#define JOB_STATE_STARTING 0x0
#define JOB_STATE_RUNNING  0x1
#define JOB_STATE_FINISHED 0x2
#define JOB_STATE_KILLED   0x3

// JobData 保存一个后台进程任务的状态。
struct JobData {
    ULONG  jobId;
    WORD   jobType;
    WORD   jobState;
    HANDLE jobObject;
    WORD   pidObject;
    HANDLE pipeRead;
    HANDLE pipeWrite;
};

// JobsController 管理所有后台 job。
class JobsController
{
public:
	Vector<JobData> jobs;

    // CreateJobData 创建后台 job 记录。
    JobData CreateJobData(ULONG taskId, WORD Type, WORD State, HANDLE object, WORD pid, HANDLE input, HANDLE output);
    // ProcessJobs 检查 job 是否结束并读取输出。
    void    ProcessJobs(Packer* packer);

    // operator new 走自定义内存分配。
    static void* operator new(size_t sz);
    // operator delete 走自定义内存释放。
    static void operator delete(void* p) noexcept;
};
