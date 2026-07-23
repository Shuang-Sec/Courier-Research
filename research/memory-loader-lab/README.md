# memory-loader-lab

这是给当前 Adaptix/direct_https_agent 研究配套的最小内存加载学习实验。

## 当前目标

先不要直接把完整 C2 agent 搬进内存加载，而是按“从简单到复杂”的方式分三步证明：

1. `hello_payload.x64.dll`：一个普通 DLL，导出 `HelloPayload` 和 `AddNumbers`。
2. `loader_plain.x64.exe`：读取 DLL 原始字节，用 MemoryModule 从内存加载并调用导出函数。
3. `loader_encrypted.x64.exe`：读取 XOR 加密后的 `hello_payload.x64.bin`，解密后再从内存加载并调用导出函数。
4. `direct_https_agent_sleep.x64.dll`：把 direct_https_agent 的 `AgentMain()` 包成 DLL 导出 `RunAgentDll()`，但只启用 sleep-only probe，不发网络请求。
5. `loader_agentdll_encrypted.x64.exe`：读取 XOR 加密后的 `direct_https_agent_sleep.x64.bin`，解密、内存加载，再调用 `RunAgentDll()`。

## 为什么先做 hello DLL

当前 direct_https_agent 是复杂 C++ PE/EXE 结构，不能一开始就直接改完整内存加载。先用 hello DLL 证明 loader 基础链路：

```text
DLL -> bytes -> MemoryLoadLibrary -> MemoryGetProcAddress -> exported function
```

再做：

```text
DLL -> encrypted bin -> decrypt -> MemoryLoadLibrary -> exported function
```

最后再验证 direct_https 代码能不能以 DLL probe 形式被内存加载：

```text
direct_https AgentMain -> RunAgentDll export -> encrypted bin -> MemoryLoadLibrary -> RunAgentDll()
```

## Build hello DLL 和基础 loader

```bash
cd research/memory-loader-lab
make clean all
```

## Build direct_https sleep-only DLL probe

```bash
cd research/memory-loader-lab
./build_direct_https_sleep_dll.sh
```

默认编译参数：

```text
DIRECT_HTTPS_SANDBOX_PROBE_STAGE=54
DIRECT_HTTPS_DELAY_BEFORE_SEND_MS=5000
```

这表示：进入 `AgentMain()` 后只 sleep 5 秒并返回 `2054`，不加载 WinINet、不读 profile、不发 C2 请求。

## Windows run example

```powershell
mkdir C:\Users\Public\memory_loader_lab
.\loader_plain.x64.exe .\hello_payload.x64.dll C:\Users\Public\memory_loader_lab\plain_loader_result.txt
.\loader_encrypted.x64.exe .\hello_payload.x64.bin C:\Users\Public\memory_loader_lab\encrypted_loader_result.txt ctf-memory-loader-key-20260624
.\loader_agentdll_encrypted.x64.exe .\direct_https_agent_sleep.x64.bin ctf-memory-loader-key-20260624
```

期望 `loader_agentdll_encrypted.x64.exe` 输出：

```text
READ_BIN=OK
DECRYPT_MAGIC=OK MZ
MEMORY_LOAD=OK
GETPROC_RunAgentDll=OK
RUN_AGENT_RC=2054
DONE=1
```

## 文件说明

- `src/hello_payload.c`：最小 DLL payload。
- `src/loader_plain.c`：明文 DLL 内存加载器。
- `src/loader_encrypted.c`：加密 hello DLL bin 内存加载器。
- `src/direct_https_dll_entry.cpp`：direct_https DLL wrapper，把 `RunAgentDll()` 转发到 `AgentMain()`。
- `src/loader_agentdll_encrypted.c`：direct_https DLL bin 内存加载器。
- `build_direct_https_sleep_dll.sh`：编译 direct_https sleep-only DLL probe。
- `third_party/MemoryModule/`：MemoryModule 最小依赖源码。
