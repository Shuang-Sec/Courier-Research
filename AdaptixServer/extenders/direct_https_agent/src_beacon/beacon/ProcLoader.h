// 文件作用：手动模块/API 解析声明：提供字符串 hash、查模块和查函数地址的接口。
#pragma once
#include <windows.h>
#include "ApiDefines.h"

// Djb2A 计算 ASCII 字符串 hash。
ULONG Djb2A(PUCHAR str);

// Djb2W 计算宽字符串 hash。
ULONG Djb2W(PWCHAR str);

// GetModuleAddress 通过模块名 hash 找 DLL 基址。
HMODULE GetModuleAddress(ULONG modHash);

// GetSymbolAddress 通过函数名 hash 找函数地址。
LPVOID GetSymbolAddress(HANDLE hModule, ULONG symbHash);