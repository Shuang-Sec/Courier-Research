// 文件作用：Base64 编解码函数声明：提供编码、解码和长度计算接口。
#pragma once

// b64_encode 把二进制数据转成 Base64 文本。
char* b64_encode(const unsigned char* in, int len);

// b64_decoded_size 估算 Base64 解码后的大小。
int b64_decoded_size(const char* in);

// b64_decode 把 Base64 文本还原成二进制数据。
int b64_decode(const char* in, unsigned char* out, int outlen);
