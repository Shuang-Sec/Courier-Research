# WPP/WPS direct_https 自研 Agent 的特色技术与原版 Adaptix 对比

## 1. 先给小白看的结论

当前版本的核心价值，不是简单把官方 Adaptix agent 的命令数量继续堆大，而是针对 WPP/WPS 这种特殊宿主，把“通信协议、进程启动、命令输出、编码转换、任务清理、构建验证”串成了一条可测量、可回滚的完整链路。

一句话概括：

> 官方 Adaptix 的 beacon_agent 是面向多种场景的通用 agent；当前版本是面向 WPP/WPS 宿主和 direct HTTPS 通道做过专项适配的功能版 agent。

它的重点改进集中在三件事：

1. 用带版本和能力协商的自研任务/结果外壳，给协议留出明确的演进空间。
2. 用多级进程启动策略和文件输出 fallback，解决主 WPP/WPS 中 cmd、PowerShell 输出回传不稳定的问题。
3. 用三次独立部署、回连监控、功能矩阵、文件哈希和清理检查，把“看起来能用”变成可复核的 release 证据。

这里的“自研”主要指协议布局、适配策略、代码组合和验证流程。项目没有声称重新发明 Windows 的 CreateProcess 或 HTTP API；真正的特色是把这些基础能力组合成适合当前宿主的工程方案。

## 2. 对照范围和版本边界

为了避免“原版”这个词太模糊，本文固定使用三个版本：

| 名称 | 版本 | 用途 |
|---|---|---|
| 官方 Adaptix 对照 | origin/main，提交 a4b80bf370f704d6843e69433bfb5c06274f57df | 对照上游 beacon_agent 的通用实现 |
| 本项目改造前基线 | a199bc15528b015cb6ae1a2affc6ac0ec5c80ad8 | 对照 direct_https 早期 schema4 result bundle 版本 |
| 当前 release | release-wpp-functional-v1，提交 72e54efee51ee70445344a81c4580142a505b0e2 | 本文介绍的最新版本 |

上游 origin/main 里有 AdaptixServer/extenders/beacon_agent，但没有 AdaptixServer/extenders/direct_https_agent。因此，当前 direct_https 不是上游同名目录的简单小补丁，而是本项目在 Adaptix 插件接口基础上单独形成的扩展路径。

从本项目改造前的 a199bc1 到当前 72e54ef，direct_https 目录的实际变更为 21 个文件，新增约 2295 行，删除约 93 行。这个数字包含协议、Go 插件、C++ agent、进程启动、任务管理和工具函数的变化，不等于“所有代码都是原创”，但能说明当前版本已经形成了一套独立的目标适配层。

## 3. 先理解整体结构

### 3.1 Adaptix 里几个容易混淆的名词

| 名词 | 小白理解 |
|---|---|
| Teamserver | 服务端，负责保存 agent、接收任务、解析结果并交给 UI |
| Go 插件 | Adaptix 服务端扩展，主要负责把 UI 命令转换成二进制任务，并把回包转换成 UI 能显示的结果 |
| C++ agent | Windows 侧代码，负责联网、取任务、执行命令、读文件和上传结果 |
| Connector | 通信连接器，负责 HTTP/HTTPS 请求和响应 |
| Commander | 命令分发器，看到 command id 后选择 CmdPwd、CmdLs、CmdPsRun 等处理函数 |
| JobsController | 后台 job 管理器，负责异步进程的状态、输出和结束清理 |
| Packer | 二进制打包器，把整数、字符串和字节数组按协议写进连续内存 |
| Envelope | 数据外壳，可以理解成信封，里面装任务或结果 |
| Section | 外壳里的分区，每个分区带类型和长度，类似带标签的盒子 |
| Capability | 能力位，告诉服务端“这个 agent 支持哪些协议版本和功能” |

### 3.2 从 UI 到 Windows 进程的完整路径

~~~mermaid
flowchart LR
    UI[Adaptix UI] --> GO[Go 插件 pl_main.go]
    GO --> TASK[命令编号与参数]
    TASK --> FRAME[LPT4 或 DHT2 任务外壳]
    FRAME --> HTTP[direct HTTPS Connector]
    HTTP --> AGENT[Windows C++ agent]
    AGENT --> CMD[Commander]
    CMD --> ROUTE[进程启动策略]
    ROUTE --> JOB[JobsController]
    JOB --> RESULT[LPR4 或兼容结果]
    RESULT --> HTTP
    HTTP --> PARSE[Go ProcessData]
    PARSE --> UI
~~~

普通命令，例如 pwd，直接走 Commander 的同步处理函数。cmd 和 PowerShell 属于后台 job：agent 启动子进程后先把 PID 告诉服务端，之后在每次回连时读取输出，最后发送 job finished。WPP/WPS 的关键难点就在中间的“子进程启动和输出回传”。

## 4. 特色一：带能力协商的自研协议外壳

### 4.1 官方 agent 的思路

官方 beacon_agent 使用 Adaptix 既有的 Packer、Connector 和 command record 体系。MainAgent 负责连接，Connector 交换数据，Commander 解析命令记录，JobsController 处理异步输出。这种设计的优点是成熟、功能覆盖广，且能同时支持 HTTP、DNS、SMB、TCP 等多种 connector。

它更像一个通用的“固定格式任务队列”：服务端和 agent 约定好字段顺序，再由双方按照同一套 Packer 读写。

### 4.2 当前版本新增的层次

当前版本在保留已有 command id、参数顺序和 legacy record 的基础上，增加了几层自研外壳：

1. DHB2 heartbeat：agent 初次上线时报告 beat schema 和 capability mask。
2. DHT2/DHR2：任务和结果增加 schema、flags、task count、body length 等边界字段。
3. Sectioned body：body 里使用 section count，再用 section type、section length、section value 组织内容。
4. LPT4/LPR4：schema4 agent 使用更中性的任务和结果 frame magic。
5. Native task/result record：把 command id 映射成 action id，把结果字段标成 text、path 等明确类型。
6. Legacy fallback：旧 agent 或旧回包仍可按原来的记录流解析，不强迫所有版本同时升级。

Go 侧的主要实现位置：

- AdaptixServer/extenders/direct_https_agent/pl_main.go:52
- AdaptixServer/extenders/direct_https_agent/pl_main.go:118
- AdaptixServer/extenders/direct_https_agent/pl_main.go:824
- AdaptixServer/extenders/direct_https_agent/pl_main.go:891
- AdaptixServer/extenders/direct_https_agent/pl_main.go:921

Windows 侧的主要实现位置：

- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp:367
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:381

### 4.3 用一个简单例子理解

早期的任务可以理解成：

~~~text
任务记录 1 | 任务记录 2 | 任务记录 3
~~~

当前的 LPT4 任务大致是：

~~~text
LPT4
schema
flags
task_count
body_length
section_count
meta_section(type + length + value)
task_section(type + length + task_id + action_id + argument_length + arguments)
~~~

这几个长度字段就像快递单上的“总重量”和“箱子大小”。解析器读到一半时，可以判断剩余数据是否足够；section type 让解析器知道当前盒子装的是元信息还是任务；action id 让 native agent 不必把一段未标记的数字直接当成命令。

结果侧 LPR4 也有类似结构：

~~~text
LPR4
schema
flags
body_length
meta_section
result_bundle_section
codec
result_record
field_type
field_length
field_bytes
~~~

### 4.4 这个改进带来的实际收益

| 收益 | 解释 |
|---|---|
| 版本可演进 | 新字段可以放进新 section，旧字段继续放在 legacy section |
| 能力可协商 | 服务端根据 agent 的 schema 和 capability 选择帧格式 |
| 错误更容易定位 | schema、flags、count、length 任意一项不符合预期时可以提前结束解析 |
| 结果类型更清楚 | text 和 path 可以分别标记，Go 侧转换逻辑更容易维护 |
| 升级过程更平滑 | 新版服务端仍能接受旧结果，过渡期不需要一次性替换全部 agent |

这项特色不是“把协议写得更复杂”，而是把以前隐含在双方代码里的假设，写成了明确的版本、能力、长度和类型字段。

## 5. 特色二：面向 WPP/WPS 的多级进程启动策略

### 5.1 为什么官方的单一路径在这里会遇到问题

官方 beacon_agent 的 CmdPsRun 主要流程是：

1. 创建匿名管道。
2. 设置 STARTF_USESTDHANDLES，让子进程 stdout 和 stderr 指向管道。
3. 优先使用保存的 token 启动进程。
4. 再尝试 CreateProcessWithTokenW 或普通 CreateProcessA。
5. 把 pipe read/write 句柄交给 JobsController。

上游代码的对照位置是 origin/main 中的：

- AdaptixServer/extenders/beacon_agent/src_beacon/beacon/Commander.cpp:850
- AdaptixServer/extenders/beacon_agent/src_beacon/beacon/JobsController.cpp:22

匿名管道本身没有问题，难点是“子进程是否可以继承这个句柄”。WPP/WPS 主宿主可能运行在特定 Job、句柄继承规则或权限上下文中。之前的真实回归已经观察到：插件型 WPS 路径可以执行，而主 WPP/WPS 的普通 CreateProcess 路径会返回 Win32 错误 5，也就是 ACCESS_DENIED。

### 5.2 当前版本的处理方式

当前版本把“启动进程”拆成多个可观测的候选路径。代码在失败后继续走下一条，同时记录 diagnostic flags 和原始错误：

1. 有输出时先准备管道，并尝试显式 handle list，只让子进程继承需要的输出句柄。
2. 对需要输出的任务，进入 file-backed output 路径，避免把 WPP/WPS 的管道句柄带过宿主边界。
3. 在文件路径下依次尝试普通 CreateProcessA。
4. 继续尝试 CREATE_BREAKAWAY_FROM_JOB。
5. 使用当前宿主 token 调用 CreateProcessAsUserA。
6. 再尝试 CreateProcessWithTokenW。
7. 调用 RtlCreateUserProcess。
8. 调用 NtCreateUserProcess。
9. 尝试 ShellExecuteExA，让系统 shell broker 创建进程。
10. 最后尝试 WMI provider 作为服务侧执行 broker。

相关代码位置：

- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:945
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:975
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1026
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1062
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1212
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1261
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1352
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1454
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1482

### 5.3 这项特色的重点

重点不是“调用的 API 越多越好”，而是把不同失败原因拆开：

- 句柄继承问题，交给 explicit handle list 或 file output 处理。
- Job 限制，交给 breakaway 或 native process route 处理。
- token 上下文问题，交给 AsUser 或 WithToken 路径处理。
- shell 代理差异，交给 ShellExecuteExA 处理。
- 服务侧可执行问题，交给 WMI route 处理。

每条路径都有对应的 diagnostic bit，失败报告中可以区分“普通创建失败”“token 打开失败”“native 创建失败”“shell route 失败”等情况。这样后续继续调试时，面对的是一张失败矩阵，而不是一句笼统的“cmd 没有返回”。

## 6. 特色三：文件输出 fallback 和完整生命周期管理

### 6.1 文件 fallback 怎样工作

当任务需要 cmd 或 PowerShell 输出时，当前版本使用按 task id 唯一命名的文件：

~~~text
C:\Users\Public\direct-https-job-<taskId>.out
~~~

子进程的标准输出和错误输出通过命令行重定向到这个文件：

~~~text
> "C:\Users\Public\direct-https-job-<taskId>.out" 2>&1
~~~

如果原命令是 cmd.exe /d /c，并且命令内部包含 && 链，代码会把整个命令体包起来，再在外层追加重定向。这样 command chain 的各段输出都会进入同一个文件。

这个办法绕开了最敏感的“子进程继承宿主管道句柄”环节。父 agent 后面把普通文件当作一个可读的输出源，仍然通过 COMMAND_JOB 的原有结果布局回传，所以服务端 UI 不需要换一套 job 语义。

主要代码位置：

- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1062
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1122
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:1509

### 6.2 为什么要增加 final drain

文件写入和进程退出不是同一时刻发生的。一个短命令可能已经退出，但最后一小段输出仍然在文件缓冲中，或者 agent 恰好在第一次轮询时读到空文件。

当前 JobsController 的顺序是：

1. 先读取当前已有输出。
2. 查询进程退出状态。
3. 发现进程已经结束后，再读取一次文件。
4. 把第二次读到的内容作为 COMMAND_JOB running output 发回。
5. 关闭句柄、删除临时文件、发送 job finished。

对应代码：

- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp:26
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp:49
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp:65
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp:103

官方 JobsController 的逻辑主要读取匿名管道，然后发现进程结束就关闭管道并删除 job。当前版本新增了 regular file 判断、退出后的最终读取和临时文件删除，解决了“进程已经结束，但最后输出还没有交付”的时间窗口。

### 6.3 这项特色的实际验证

三次独立 release 部署都完成了：

- WPP/WPS 的 cmd 标记输出。
- PowerShell 标记输出和路径查询。
- F0 输出矩阵 10/10。
- 完整 WPP/WPS 功能矩阵 17/17。
- 远程 C:\Users\Public\direct-https-job-*.out 清理。

因此，这个改进的价值体现在“输出结果可靠且清理完整”，而不仅仅是“子进程返回了一个 PID”。

## 7. 特色四：PowerShell 文件输出编码归一化

### 7.1 问题来源

Windows PowerShell 5.1 把输出重定向到普通文件时，常见结果是 UTF-16LE，并且文件开头带 FF FE BOM。Adaptix 旧的 job 文本显示路径通常按 agent OEM code page 解析。

如果直接把 UTF-16LE 字节当作单字节文本送回，结果中会出现大量零字节或乱码。cmd 通过控制台管道返回的编码路径和 PowerShell 通过普通文件重定向返回的编码路径也不完全一样。

### 7.2 当前处理

agent 的 ReadDataFromAnonPipe 增加了 regularFile 参数。对于 file-backed job：

1. 先读取普通文件。
2. 检查开头是否为 FF FE。
3. 计算 UTF-16LE 字符数量。
4. 使用 WideCharToMultiByte 转换到当前 agent OEM code page。
5. 再按原有 COMMAND_JOB 布局交给 Go 侧。

代码位置：

- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/utils.cpp:36
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/utils.cpp:87
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ApiLoader.h:73
- AdaptixServer/extenders/direct_https_agent/pl_main.go:1200

这项改动看起来很小，但它直接决定了 PowerShell 的“命令成功”能否变成 UI 中可读的文本。

## 8. 特色五：完整但有边界的 14 项功能面

当前 release 锁定的注册命令是：

~~~text
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
~~~

Go 的 CreateCommand 负责把这些名称转换为 command id 和参数。C++ 的 Commander 再把 command id 映射到 handler。schema4 native action id 也有对应映射，例如：

~~~text
COMMAND_DISKS -> selfC2ActionDisks -> 0x0209
COMMAND_PS_RUN -> selfC2ActionRunProcess -> 0x0102
COMMAND_PWD -> selfC2ActionPwd -> 0x0201
~~~

实现位置：

- AdaptixServer/extenders/direct_https_agent/pl_main.go:974
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:333
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp:570

其中：

- disks 根据靶机实际逻辑磁盘返回盘符和类型，盘符数量完全以靶机实测结果为准。
- upload 复用 MemorySaver，先在服务端保存内容，再由 agent 写入目标文件。
- download 复用 Downloader 和现有 task/result 机制，服务端按分片收集内容。
- file CRUD 使用同一组路径参数和错误布局，方便 UI 文件浏览器继续工作。

这里需要一个重要的诚实比较：官方 beacon_agent 的命令面更宽，包含 BOF、pivot、tunnel、交互 shell、进程管理等能力。当前 direct_https release 的命令数量更窄，但范围更聚焦，且当前注册的 14 项已经在 WPP/WPS 主宿主完成实测。这是“专项稳定性优先”，不是“功能数量全面超过官方”。

## 9. 特色六：轻量 direct HTTPS 连接器和可控构建开关

官方 beacon_agent 是多 connector、宽功能的通用 agent。当前版本的目标是固定在 direct HTTPS，并使用 lite WinINet connector：

- 初始化网络状态推迟到第一次 Exchange。
- 保留 Connector 合同，替换成当前 release 需要的最小 HTTP/HTTPS 路径。
- profile、listener、sleep、jitter 和 URI 都被写入 build metadata。
- 通过 Makefile 的编译开关区分 probe、heartbeat-only、hello-only、file-commands-only 和完整功能构建。

最终 package 的 build-meta.json 记录了：

~~~text
lite_connector = true
lazy_wininet_init = true
api_hashing = false
learning_minimal = false
file_commands_only = false
heartbeat_only = false
hello_only = false
sleep = 10s
jitter = 0
~~~

相关位置：

- AdaptixServer/extenders/direct_https_agent/src_beacon/Makefile:35
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp:72
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ApiLoader.h:40
- AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ConnectorHTTP.cpp:1

这项改进的重点是“减少本次目标不需要的初始化变量，并把构建选择记录下来”。它让实验中的 hello、文件命令、完整功能版本可以从同一代码树生成，并且每次都能从 build-meta.json 查到当时的开关。

## 10. 特色七：把验证流程当作产品的一部分

官方框架提供的是通用 agent 和插件接口；当前项目额外建立了面向目标宿主的 release 门禁：

1. direct_https_agent Go 单元测试和协议测试。
2. C++ x64/x86 对象构建。
3. profile DLL、cache.dat、WPS 代理和 runtime plugin 的构建。
4. 每个关键文件的 SHA-256。
5. Kaspersky 静态扫描。
6. Scan_System_Memory。
7. 每轮等待旧任务释放后重新发起新鲜 Scan_Qscan。
8. 720 秒 WPP/WPS 回连监控。
9. WPP/WPS 完整命令矩阵。
10. 文件上传下载 SHA-256 比对。
11. 目标进程 Responding 检查。
12. scratch、job output、临时上传下载文件清理。

当前 release 的三轮结果：

| 部署 | Qscan processed/detected/errors | 回连 WPP/WPS | WPP/WPS 功能矩阵 | F0 | disks | transfer |
|---|---:|---:|---:|---:|---:|---|
| release-run-2b | 3548/0/0 | 65/65 | 17/17 | 10/10 | 2/2 | pass |
| release-run-3 | 3572/0/0 | 60/64 | 17/17 | 10/10 | 2/2 | pass |
| release-run-4 | 3572/0/0 | 65/65 | 17/17 | 10/10 | 2/2 | pass |

三轮都保留了构建、部署、扫描、功能 JSON、回连监控和 cleanup 证据。这让“稳定”有了具体判定条件：同一哈希的产物，换一个全新部署窗口，仍然能完成回连、功能和清理。

证据目录：

- LOCAL_CANDIDATE_ROOT/release-run-2b/
- LOCAL_CANDIDATE_ROOT/release-run-3/
- LOCAL_CANDIDATE_ROOT/release-run-4/

## 11. 与原版 Adaptix beacon_agent 的重点对比表

| 对比维度 | 官方 beacon_agent | 当前 WPP/WPS direct_https agent | 重点变化 |
|---|---|---|---|
| 定位 | 通用 Adaptix agent | direct HTTPS 专项 agent | 从通用能力转向固定宿主适配 |
| 连接器 | HTTP、DNS、SMB、TCP 等多种 connector | lite WinINet direct HTTPS | 减少本次目标不需要的连接器状态 |
| 任务协议 | 既有 Packer 和 command record | DHB2、DHT2、LPT4、LPR4、section、native codec，并保留 legacy | 版本、能力、长度和类型更明确 |
| 命令启动 | 匿名管道，token 路径和普通 CreateProcess | handle list、file output、breakaway、AsUser、WithToken、RTL、NT、Shell、WMI 多级策略 | 面向 WPP/WPS 主宿主的权限和 Job 差异 |
| 输出来源 | 主要是 pipeRead | pipeRead 或 task id 对应的普通输出文件 | 绕开输出管道继承问题 |
| job 结束 | 查询退出后关闭对象和管道 | 退出后 final drain，再关闭句柄并删除文件 | 降低短命令最后输出丢失 |
| 编码 | 通用命令输出路径 | 对 PowerShell UTF-16LE 文件输出转换到 OEM code page | 让文件重定向结果可读 |
| 命令范围 | 更宽，包含 BOF、pivot、tunnel、shell 等 | 14 项已注册命令 | 范围更窄，但当前范围有 WPP/WPS 实测 |
| 兼容策略 | 以通用 agent 协议为主 | 新外壳与旧 record 双路径解析 | 方便阶段性升级和回滚 |
| 诊断 | 通用错误和任务状态 | 原始 Win32/NT 错误加 diagnostic bit | 能定位具体失败路线 |
| 发布方式 | 框架级构建 | 候选 tag、完整包、文件哈希、三轮部署证据 | 把目标验证纳入 release 定义 |

## 12. 哪些内容算“创新”，哪些内容是功能恢复

为了让评价更准确，可以分成四层：

### 第一层：项目级最强特色

- DHB2 能力协商和 DHT2/DHR2 外壳。
- LPT4/LPR4 section/native task/result 体系。
- WPP/WPS 多级进程启动与 file-backed output fallback。
- final drain、编码归一化和清理绑定在同一个 job 生命周期里。

这些内容组合起来，解决的是“协议能演进”和“宿主差异下结果仍能回来”两个系统问题。

### 第二层：目标适配型特色

- lite WinINet connector。
- 延迟网络初始化。
- 诊断位和构建开关。
- 主 WPP/WPS 与插件型 WPS 的同一套功能矩阵。

这些内容不一定是通用框架需要的能力，但对当前固定靶机很有价值。

### 第三层：工程质量特色

- 每阶段一个 tag。
- 源码和构建包独立留存。
- 每个 artifact 有 SHA-256。
- 新鲜 Qscan 与历史统计分开记录。
- 进程存活、功能结果和 cleanup 都有原始证据。

这部分往往决定了一个 agent 是“偶尔能跑”，还是“团队可以反复拿来验证”。

### 第四层：功能恢复

- hello、pwd、disks、文件 CRUD、upload/download、cmd、PowerShell 本身属于功能恢复。
- 它们的特色在于复用现有 Adaptix UI、opcode、参数顺序和 task/result 语义，并在 WPP/WPS 主宿主完成真实回归。

因此，当前版本的创新表达应当是“目标专项适配和协议/验证工程创新”，而不是把每一个基础文件命令都描述成新发明。

## 13. 对当前版本的准确评价

当前 agent 相比官方 beacon_agent 的主要提升，是在 WPP/WPS direct HTTPS 场景下的：

- 宿主兼容性。
- 命令输出可靠性。
- 协议演进能力。
- 结果编码一致性。
- 失败诊断能力。
- 可复跑和可审计性。

相应的取舍也很明确：

- 连接器范围更窄。
- 当前 v1 命令面更窄。
- tunnel、terminal、pivot、jobs kill、terminate、save memory 的完整 UI 流程没有混入本次 release。
- 代码路径更多，维护时需要继续保持每条 fallback 的测试覆盖。

这是一种“围绕固定目标做深”的设计。它不追求在所有 Adaptix 场景里替代通用 beacon_agent，而是让当前 WPP/WPS 目标上的 14 项功能具备稳定、清晰、可追溯的运行基础。

## 14. 当前 release 的留存位置

- 最新源码和构建包留存清单：LOCAL_CANDIDATE_ROOT/preserved-latest-20260721/PRESERVATION-MANIFEST.md
- 最新创新对比文档：LOCAL_CANDIDATE_ROOT/INNOVATIONS-VS-ORIGINAL-ADAPTIX.md
- 最终 release 包：LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/
- 实现细节入门说明：LOCAL_CANDIDATE_ROOT/IMPLEMENTATION-OVERVIEW.md

后续继续开发时，建议先保留当前 tag 和留存目录，再从新的候选编号开始。这样每一次新功能带来的变化，都可以和当前 release 的协议、功能、哈希、回连和清理结果逐项比较。
