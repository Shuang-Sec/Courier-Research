// 文件作用：连接器抽象类：规定所有通信连接器都要实现设置配置、发送、接收、交换和关闭。
#pragma once

#include "WaitMask.h"

// Connector 是通信层的抽象接口，HTTP/SMB/TCP 等连接器都要按这个形状实现。
class Connector
{
public:
	// SetProfile 设置通信参数和首次心跳。
	virtual BOOL SetProfile(void* profile, BYTE* beat, ULONG beatSize) = 0;

	// WaitForConnection 等待连接建立；HTTP 场景默认直接成功。
	virtual BOOL WaitForConnection() { return TRUE; }

	// IsConnected 判断连接是否可用；HTTP 场景默认可用。
	virtual BOOL IsConnected() { return TRUE; }

	// Disconnect 断开连接；HTTP 场景当前没有额外动作。
	virtual void Disconnect() {}

	// Exchange 完成一次发送和接收。
	virtual void Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey) = 0;

	// RecvData 返回收到的任务数据。
	virtual BYTE* RecvData() = 0;
	// RecvSize 返回收到的数据大小。
	virtual int   RecvSize() = 0;
	// RecvClear 清空接收缓冲区。
	virtual void  RecvClear() = 0;

	// Sleep 控制两次通信之间等待多久。
	virtual void Sleep(HANDLE wakeupEvent, ULONG workingSleep, ULONG sleepDelay, ULONG jitter, BOOL hasOutput)
	{
		if (!hasOutput)
			WaitMask(workingSleep, sleepDelay, jitter);
	}

	// CloseConnector 关闭连接器资源。
	virtual void CloseConnector() = 0;

	// 析构函数让子类能安全释放资源。
	virtual ~Connector() {}
};
