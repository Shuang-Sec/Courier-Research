// 文件作用：RC4 加解密函数声明：暴露初始化、加密和解密接口。
#pragma once

// RC4Init 初始化 RC4 状态盒。
void RC4Init(unsigned char* key, unsigned char* S, int keyLength);

// RC4EncryptDecrypt 用状态盒处理数据。
void RC4EncryptDecrypt(unsigned char* data, int dataLength, unsigned char* S);

// EncryptRC4 用 key 加密数据。
void EncryptRC4(unsigned char* data, int dataLength, unsigned char* key, int keyLength);

// DecryptRC4 用 key 解密数据。
void DecryptRC4(unsigned char* data, int dataLength, unsigned char* key, int keyLength);