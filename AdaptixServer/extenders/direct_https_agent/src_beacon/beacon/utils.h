// 文件作用：Windows agent 通用工具声明：暴露内存、系统信息、字符串和时间工具接口。
#pragma once

#include <windows.h>

//////////

// MemAllocLocal 申请本地内存。
LPVOID MemAllocLocal(DWORD bufferSize);

// MemReallocLocal 调整本地内存大小。
LPVOID MemReallocLocal(LPVOID buffer, DWORD bufferSize);

// MemFreeLocal 清零并释放本地内存。
void MemFreeLocal(LPVOID* buffer, DWORD bufferSize);

//////////

// ReadDataFromAnonPipe 读取子进程管道输出；regularFile 为普通文件 fallback。
BYTE* ReadDataFromAnonPipe(HANDLE hPipe, ULONG* bufferSize, BOOL regularFile = FALSE);

// NormalizeProcessOutput 把 PowerShell 文件重定向产生的 UTF-16LE 输出转成 OEM code page。
BYTE* NormalizeProcessOutput(BYTE* buffer, ULONG* bufferSize);

//////////

// GenerateRandom32 生成 32 位随机数。
ULONG GenerateRandom32();

// GetGmtOffset 获取时区偏移。
BYTE GetGmtOffset();

// IsElevate 判断是否管理员权限。
BOOL IsElevate();

// GetInternalIpLong 获取内网 IPv4。
ULONG GetInternalIpLong();

// _GetUserName 获取用户名。
CHAR* _GetUserName();

// _GetHostName 获取主机名。
CHAR* _GetHostName();

// _GetDomainName 获取域名/工作组。
CHAR* _GetDomainName();

// _GetProcessName 获取进程名。
CHAR* _GetProcessName();

//////////

// StrChrA 查找字符。
CHAR* StrChrA(CHAR* str, CHAR c);

// StrTokA 分割字符串。
CHAR* StrTokA(CHAR* str, CHAR* delim);

// StrIndexA 查找字符下标。
DWORD StrIndexA(CHAR* str, CHAR target);

// StrLCopyA 限长复制字符串。
LPSTR StrLCopyA(LPSTR dst, LPCSTR src, int iMaxLength);

// StrLenA 计算字符串长度。
DWORD StrLenA(const CHAR* str);

// StrCmpA 比较字符串。
DWORD StrCmpA(const CHAR* str1, const CHAR* str2);

// StrNCmpA 比较前 n 个字符。
DWORD StrNCmpA(CHAR* str1, CHAR* str2, SIZE_T n);

// StrCmpLowA 忽略大小写比较 ASCII 字符串。
DWORD StrCmpLowA(CHAR* str1, CHAR* str2);

// StrCmpLowW 忽略大小写比较宽字符串。
DWORD StrCmpLowW(WCHAR* str1, WCHAR* str2);

// FileTimeToUnixTimestamp 把 FILETIME 转成 Unix 时间。
ULONG FileTimeToUnixTimestamp(FILETIME ft);

// GetSystemTimeAsUnixTimestamp 获取当前 Unix 时间。
ULONG GetSystemTimeAsUnixTimestamp();
