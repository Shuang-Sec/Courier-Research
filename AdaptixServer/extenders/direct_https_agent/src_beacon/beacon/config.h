// 文件作用：编译期 profile 访问器声明：声明读取 profile、大小和 IAT hiding 开关的函数。
#pragma once

// getProfile 返回内嵌 profile 数据。
char* getProfile();

// getProfileSize 返回 profile 长度。
unsigned int getProfileSize();

// isIatHidingEnabled 返回是否启用 IAT hiding。
int isIatHidingEnabled();
