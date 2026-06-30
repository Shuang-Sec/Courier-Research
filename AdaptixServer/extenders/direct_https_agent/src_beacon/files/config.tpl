// 文件作用：构建 payload 时复制到 objects_http/config.cpp 的 profile 访问器模板。
// getProfile 返回编译时写入的 PROFILE 字节串。
char* getProfile()
{
	return (char*) PROFILE;
}

// getProfileSize 返回 PROFILE_SIZE，也就是 profile 的字节长度。
unsigned int getProfileSize()
{
	return PROFILE_SIZE;
}

// isIatHidingEnabled 返回当前构建是否启用了 IAT hiding。
int isIatHidingEnabled()
{
#if defined(IAT_HIDING)
	return 1;
#else
	return 0;
#endif
}
