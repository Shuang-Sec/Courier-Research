// 文件作用：RC4 加解密实现：agent 和服务端之间用同一个函数对数据做对称加密/解密。
#include "Crypt.h"

// RC4Init 根据 key 初始化 RC4 状态盒 S。
void RC4Init(unsigned char* key, unsigned char* S, int keyLength) {
    int i, j = 0;
    unsigned char temp;

    for (i = 0; i < 256; i++) {
        S[i] = (unsigned char)i;
    }

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLength]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

// RC4EncryptDecrypt 用 RC4 字节流对数据逐字节异或，既可加密也可解密。
void RC4EncryptDecrypt(unsigned char* data, int dataLength, unsigned char* S) {
    int i = 0, j = 0, k;
    unsigned char temp;

    for (k = 0; k < dataLength; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

        temp = S[i];
        S[i] = S[j];
        S[j] = temp;

        data[k] ^= S[(S[i] + S[j]) % 256];
    }
}

// EncryptRC4 包装 RC4 初始化和处理流程，用 key 加密数据。
void EncryptRC4(unsigned char* data, int dataLength, unsigned char* key, int keyLength) {
    unsigned char S[256];
    RC4Init(key, S, keyLength);
    RC4EncryptDecrypt(data, dataLength, S);
}

// DecryptRC4 包装 RC4 初始化和处理流程；RC4 对称，所以解密流程和加密相同。
void DecryptRC4(unsigned char* data, int dataLength, unsigned char* key, int keyLength) {
    EncryptRC4(data, dataLength, key, keyLength);
}