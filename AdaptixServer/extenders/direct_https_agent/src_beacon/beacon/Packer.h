// 文件作用：Windows 侧二进制打包器声明：提供 Pack/Unpack 数字、字符串、字节数组的接口。
#pragma once
#include "ApiLoader.h"
#include "utils.h"

// Packer 负责按 direct_https 协议打包和解包二进制字段。
class Packer
{
	DWORD size;
	DWORD capacity;
	BYTE* buffer;
	DWORD index;

public:
	// 默认构造函数创建可写缓冲区。
	Packer();
	// 读取构造函数用已有数据创建解析器。
	Packer(BYTE* buffer, ULONG size);
	// 析构函数。
	~Packer();

	// Set32 在指定位置写入 4 字节值。
	VOID Set32(ULONG index, ULONG value);
	// EnsureCapacity 保证缓冲区够大。
	VOID EnsureCapacity(ULONG needed);

	// Pack64 写入 8 字节整数。
	VOID Pack64(ULONG64 value);
	// Pack32 写入 4 字节整数。
	VOID Pack32(ULONG value);
	// Pack16 写入 2 字节整数。
	VOID Pack16(WORD value);
	// Pack8 写入 1 字节整数。
	VOID Pack8(BYTE value);
	// PackBytes 写入长度加字节内容。
	VOID PackBytes(PBYTE data, ULONG data_size);
	// PackFlatBytes 只写入原始字节。
	VOID PackFlatBytes(PBYTE data, ULONG data_size);
	// PackStringA 写入普通字符串。
	VOID PackStringA(LPSTR str);

	// Unpack8 读取 1 字节。
	BYTE  Unpack8();
	// Unpack32 读取 4 字节。
	ULONG Unpack32();
	// UnpackBytes 读取长度加字节内容。
	BYTE* UnpackBytes(ULONG* size);
	// UnpackBytesCopy 读取并复制字节内容。
	BYTE* UnpackBytesCopy(ULONG* size);

	// Clear 清空缓冲区。
	VOID  Clear(BOOL renew);
	// data 返回缓冲区指针。
	PBYTE data();
	// datasize 返回当前数据长度。
	ULONG datasize();

	// operator new 走自定义内存分配。
	static void* operator new(size_t sz);
	// operator delete 走自定义内存释放。
	static void operator delete(void* p) noexcept;
};