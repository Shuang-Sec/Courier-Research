// 文件作用：API 加载器声明：定义模块句柄表、WinAPI 函数表、NTAPI 函数表和 ApiLoad 入口。
#pragma once

#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <psapi.h>
#include "ntdll.h"

#ifndef DIRECT_HTTPS_FILE_COMMANDS_ONLY
#define DIRECT_HTTPS_FILE_COMMANDS_ONLY 0
#endif

#define TEB NtCurrentTeb()
#define DECL_API(x) decltype(x) * x

// memset/memcpy 是极简运行时函数声明，避免依赖系统 CRT。
extern void* __cdecl memset(void*, int, size_t);
extern void* __cdecl memcpy(void*, const void*, size_t);

// HdChrA 返回 ASCII 字符，当前主要作为字符串处理占位函数。
CHAR HdChrA(CHAR c);
// HdChrW 返回宽字符，当前主要作为字符串处理占位函数。
WCHAR HdChrW(WCHAR c);

// SYSMODULES 保存常用 DLL 的模块句柄。
struct SYSMODULES 
{
	HMODULE Kernel32;
	HMODULE Ntdll;
	HMODULE Iphlpapi;
	HMODULE Advapi32;
	HMODULE Shell32;
	HMODULE Ole32;
	HMODULE OleAut32;
};

// WINAPIFUNC 保存 agent 常用 WinAPI 的函数指针。
struct WINAPIFUNC
{
	// kernel32
	DECL_API(CopyFileA);
	DECL_API(CreateDirectoryA);
	DECL_API(CreateFileA);
	DECL_API(CreatePipe);
	DECL_API(CreateProcessA);
	DECL_API(CreateProcessAsUserA);
	DECL_API(CreateProcessWithTokenW);
	DECL_API(OpenProcess);
	DECL_API(ShellExecuteExA);
	DECL_API(SetHandleInformation);
	DECL_API(InitializeProcThreadAttributeList);
	DECL_API(UpdateProcThreadAttribute);
	DECL_API(DeleteProcThreadAttributeList);
	DECL_API(DeleteFileA);
	DECL_API(FindClose);
	DECL_API(FindFirstFileA);
	DECL_API(FindNextFileA);
	DECL_API(GetACP);
	DECL_API(GetComputerNameExA);
	DECL_API(GetCurrentDirectoryA);
	DECL_API(GetDriveTypeA);
	DECL_API(GetExitCodeProcess);
	DECL_API(GetProcessId);
	DECL_API(GetFileSize);
	DECL_API(GetFileAttributesA);
	DECL_API(GetFullPathNameA);
	DECL_API(GetLastError);
	DECL_API(GetLogicalDrives);
	DECL_API(GetOEMCP);
	DECL_API(WideCharToMultiByte);
	DECL_API(GetModuleBaseNameA);
	DECL_API(GetModuleHandleA);
	DECL_API(GetProcAddress);
	DECL_API(GetLocalTime);
	DECL_API(GetSystemTimeAsFileTime);
	DECL_API(GetTickCount);
	DECL_API(GetTimeZoneInformation);
	DECL_API(HeapAlloc);
	DECL_API(HeapCreate);
	DECL_API(HeapDestroy);
	DECL_API(HeapReAlloc);
	DECL_API(HeapFree);
	DECL_API(IsWow64Process);
	DECL_API(LoadLibraryA);
	DECL_API(LocalAlloc);
	DECL_API(LocalFree);
	DECL_API(LocalReAlloc);
	DECL_API(MoveFileA);
	DECL_API(PeekNamedPipe);
	DECL_API(ReadFile);
	DECL_API(RemoveDirectoryA);
	DECL_API(SetCurrentDirectoryA);
	DECL_API(Sleep);
	DECL_API(WriteFile);
	
	// iphlpapi
	DECL_API(GetAdaptersInfo);

	// advapi32
	DECL_API(GetTokenInformation);
	DECL_API(GetUserNameA);

	// ole32/oleaut32 COM entry points used by the WMI execution broker.
	DECL_API(CoInitializeEx);
	DECL_API(CoInitializeSecurity);
	DECL_API(CoCreateInstance);
	DECL_API(CoSetProxyBlanket);
	DECL_API(CoUninitialize);
	DECL_API(SysAllocString);
	DECL_API(SysFreeString);
	DECL_API(VariantInit);
	DECL_API(VariantClear);
};

// NTAPIFUNC 保存 agent 常用 NTAPI 的函数指针。
struct NTAPIFUNC
{
	DECL_API(NtClose);
	DECL_API(NtQuerySystemInformation);
	DECL_API(NtOpenProcessToken);
	DECL_API(NtTerminateProcess);
	DECL_API(RtlGetVersion);
	DECL_API(RtlCreateProcessParameters);
	DECL_API(RtlDestroyProcessParameters);
	DECL_API(RtlCreateUserProcess);
	DECL_API(NtCreateUserProcess);
	DECL_API(RtlExitUserThread);
	DECL_API(RtlExitUserProcess);
	DECL_API(RtlIpv4StringToAddressA);
	DECL_API(RtlRandomEx);
	DECL_API(RtlNtStatusToDosError);
};

extern SYSMODULES* SysModules;
extern WINAPIFUNC* ApiWin;
extern NTAPIFUNC*  ApiNt;
extern DWORD       ApiLoadProbeCode;

// ApiLoad 初始化上面的模块句柄表和函数指针表。
BOOL ApiLoad();
