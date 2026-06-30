// 文件作用：睡眠控制函数声明：提供带抖动的等待和基础 sleep 包装。
#pragma once
#include "ApiLoader.h"
#include "utils.h"

// WaitMask 根据工作时间、sleep 和 jitter 等待。
void WaitMask(ULONG worktime, ULONG sleepTime, ULONG jitter);

// mySleep 是 Sleep 的简单包装。
void mySleep(ULONG ms);
