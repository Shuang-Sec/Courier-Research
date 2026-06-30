// 文件作用：Windows 侧二进制打包器实现：负责把命令参数和回包数据按协议写入/读出缓冲区。
#include "Packer.h"

// Packer::operator new 使用本项目的内存分配函数创建打包器。
void* Packer::operator new(size_t sz) 
{
    void* p = MemAllocLocal(sz);
    return p;
}

// Packer::operator delete 释放打包器对象占用的本地内存。
void Packer::operator delete(void* p) noexcept 
{
    MemFreeLocal(&p, sizeof(Packer));
}

// Packer 默认构造函数创建一个可写的空缓冲区。
Packer::Packer()
{       
    this->capacity = 4096;
    this->buffer = (BYTE*) MemAllocLocal(this->capacity);
    this->size   = 0;
    this->index  = 0;
}

// Packer 读取构造函数用已有字节创建解析器。
Packer::Packer(BYTE* buffer, ULONG size)
{
    this->buffer   = buffer;
    this->size     = size;
    this->capacity = size;
    this->index    = 0;
}

// Packer 析构函数当前不主动释放内存，主要保持对象接口完整。
Packer::~Packer(){}

// Set32 在缓冲区指定位置按大端顺序写入 4 字节整数，常用于回填包长度。
VOID Packer::Set32(ULONG index, ULONG value)
{
    PUCHAR place = this->buffer + index;
    place[0] = (value >> 24) & 0xFF;
    place[1] = (value >> 16) & 0xFF;
    place[2] = (value >> 8 ) & 0xFF;
    place[3] = (value      ) & 0xFF;
}

// EnsureCapacity 确保缓冲区够大；不够就重新分配更大的空间。
VOID Packer::EnsureCapacity(ULONG needed)
{
    if (this->index + needed > this->capacity) {
        ULONG new_cap = this->capacity ? (this->capacity * 2) : 4096;
        if (new_cap < this->index + needed)
            new_cap = this->index + needed + 1024;

        this->buffer = (BYTE*)MemReallocLocal(this->buffer, new_cap);
        this->capacity = new_cap;
    }
}

// Pack64 按大端顺序写入 8 字节整数。
VOID Packer::Pack64( ULONG64 value ) 
{
    this->EnsureCapacity(sizeof(ULONG64));


    PUCHAR place = (PUCHAR) this->buffer + this->index;
    place[0] = (value >> 56) & 0xFF;
    place[1] = (value >> 48) & 0xFF;
    place[2] = (value >> 40) & 0xFF;
    place[3] = (value >> 32) & 0xFF;
    place[4] = (value >> 24) & 0xFF;
    place[5] = (value >> 16) & 0xFF;
    place[6] = (value >> 8 ) & 0xFF;
    place[7] = (value      ) & 0xFF;

    this->size  += sizeof(ULONG64);
    this->index += sizeof(ULONG64);
}

// Pack32 按大端顺序写入 4 字节整数。
VOID Packer::Pack32(ULONG value)
{
    this->EnsureCapacity(sizeof(ULONG));

    PUCHAR place = this->buffer + this->index;
    place[0] = (value >> 24) & 0xFF;
    place[1] = (value >> 16) & 0xFF;
    place[2] = (value >> 8 ) & 0xFF;
    place[3] = (value      ) & 0xFF;

    this->size  += sizeof(ULONG);
    this->index += sizeof(ULONG);
}

// Pack16 按大端顺序写入 2 字节整数。
VOID Packer::Pack16(WORD value)
{
    this->EnsureCapacity(sizeof(WORD));

    PUCHAR place = this->buffer + this->index;
    place[0] = (value >> 8) & 0xFF;
    place[1] = (value     ) & 0xFF;

    this->size  += sizeof(WORD);
    this->index += sizeof(WORD);
}

// Pack8 写入 1 字节整数。
VOID Packer::Pack8(BYTE value)
{
    this->EnsureCapacity(sizeof(BYTE));

    (this->buffer + this->index)[0] = value;

    this->size  += 1;
    this->index += 1;
}

// PackBytes 先写长度，再写字节数组内容。
VOID Packer::PackBytes(PBYTE data, ULONG data_size)
{
    this->Pack32(data_size);

    if (data_size) {
        EnsureCapacity(data_size);
        memcpy(this->buffer + this->index, data, data_size);
        this->index += data_size;
        this->size = this->index;
    }
}

// PackStringA 把 C 字符串按 bytes 格式写入。
VOID Packer::PackStringA(LPSTR str)
{
    ULONG length = StrLenA(str); // +1;
    this->PackBytes( (BYTE*) str, length);
}

// PackFlatBytes 直接写入原始字节，不额外写长度。
VOID Packer::PackFlatBytes(PBYTE data, ULONG data_size)
{
    if (data_size) {
        EnsureCapacity(data_size);
        memcpy(this->buffer + this->index, data, data_size);
        this->index += data_size;
        this->size = this->index;
    }
}


// data 返回内部缓冲区指针。
PBYTE Packer::data()
{
    return this->buffer;
}

// datasize 返回当前已经写入的数据长度。
ULONG Packer::datasize()
{
    return this->index;
}

// Clear 清空打包器；需要时重新申请一块干净缓冲区。
VOID Packer::Clear(BOOL renew)
{
    if (!renew) {
        if (this->buffer)
            MemFreeLocal((LPVOID*)&this->buffer, this->capacity);
        this->buffer   = NULL;
        this->capacity = 0;
        this->size     = 0;
        this->index    = 0;
        return;
    }
    else {
        if (this->buffer == NULL) {
            this->capacity = 4096;
            this->buffer = (BYTE*)MemAllocLocal(this->capacity);
        } 
        else if (this->capacity > 0x100000) { // 1MB
            MemFreeLocal((LPVOID*)&this->buffer, this->capacity);
            this->capacity = 4096;
            this->buffer = (BYTE*)MemAllocLocal(this->capacity);
        }
        else {
            memset(this->buffer, 0, this->capacity);
        }

        this->index = 0;
        this->size = 0;
    }
}

// Unpack8 从当前读取位置取 1 字节。
BYTE Packer::Unpack8()
{
    ULONG value = 0;
    if (this->size - this->index < 1)
        return 0;

    memcpy(&value, this->buffer + this->index, 1);

    this->index += 1;

    return value;
}

// Unpack32 从当前读取位置拷贝 4 字节到 ULONG，供命令解析使用。
ULONG Packer::Unpack32()
{
    ULONG value = 0;
    if ( this->size - this->index < 4 )
        return 0;

    memcpy(&value, this->buffer + this->index, 4);

    this->index += 4;

    return value;
}

// UnpackBytes 先读长度，再返回指向内部数据的指针。
BYTE* Packer::UnpackBytes(ULONG* str_size)
{
    *str_size = this->Unpack32();

    if ( this->size - this->index < *str_size )
        return NULL;

    if (*str_size == 0)
        return NULL;

    BYTE* out = this->buffer + this->index;
    this->index += *str_size;

    return out;
}

// UnpackBytesCopy 先读长度，再复制一份新的字节数组返回。
BYTE* Packer::UnpackBytesCopy(ULONG* str_size)
{
    *str_size = this->Unpack32();

    if (this->size - this->index < *str_size)
        return NULL;

    if (*str_size == 0)
        return NULL;

    BYTE* out = (PBYTE) MemAllocLocal(*str_size);
    memcpy(out, this->buffer + this->index, *str_size);

    this->index += *str_size;

    return out;
}