# WPP/WPS direct_https 自研 Agent 工作说明（入门版）

## 1. 这份文档解决什么问题

这是一份面向初学者的工作说明，解释本轮 direct_https 自研 Agent 从一个只有 hello 的稳定版本，逐步恢复到带有命令执行、文件操作、磁盘枚举、上传和下载能力的完整版本。

文档会回答这些问题：

- WPP、WPS、Agent、服务端和回连分别是什么。
- 一个命令从界面发出后，怎样到达 Windows 靶机，再怎样回到界面。
- 为什么主 wpp.exe / wps.exe 的 cmd 和 PowerShell 曾经出现 ACCESS_DENIED。
- 这次在 Go 服务端插件和 Windows C++ Agent 中分别做了哪些工作。
- 文件输出后备路径怎样工作，为什么它能解决主宿主的输出捕获问题。
- PowerShell 的编码问题怎样处理。
- disks、文件 CRUD、上传和下载怎样测试。
- Kaspersky 三层扫描分别测什么，三次真实部署得到了什么结果。
- 当前版本已经覆盖的范围、仍然保留到后续候选的范围，以及怎样复核全部证据。

关联报告：

- [最终候选结果报告](LOCAL_CANDIDATE_ROOT/RESULT.md)
- [发布包清单](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/MANIFEST.md)
- [阶段总报告](LOCAL_STAGE_SUMMARY)

## 2. 先看结论

本轮最终形成了一个带当前注册命令面的 direct_https Agent 版本：

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

同一批制品完成了三次独立的新鲜部署：

| 部署 | WPP/WPS 脚本矩阵 | 主命令检查 | 磁盘检查 | 文件传输 | 新鲜 Qscan |
|---|---:|---:|---:|---|---|
| release-run-2b | 17/17 | 10/10 | 2/2 | 哈希匹配 | 3548/0/0 |
| release-run-3 | 17/17 | 10/10 | 2/2 | 哈希匹配 | 3572/0/0 |
| release-run-4 | 17/17 | 10/10 | 2/2 | 哈希匹配 | 3572/0/0 |

Qscan 表格中的三个数字依次是：

~~~text
processed / detected / errors
已处理数量 / 检测数量 / 错误数量
~~~

三轮部署还分别完成了：

- cache.dat、krpt.dll、krpt.agent.dll 静态扫描。
- 系统内存扫描。
- 720 秒回连监视。
- WPP 和 WPS 两种主宿主的完整功能矩阵。
- 上传、下载和本地 SHA-256 哈希核对。
- 远程 scratch 目录和临时输出文件清理。

源码位置和版本记录：

- 源码仓库：LOCAL_ADAPTIXC2_ROOT
- 源码 commit：72e54efee51ee70445344a81c4580142a505b0e2
- 本地 release tag：release-wpp-functional-v1
- 候选目录：LOCAL_CANDIDATE_ROOT

## 3. 背景：原来的系统是什么样

### 3.1 什么是 Agent

这里的 Agent 可以理解为运行在 Windows 靶机上的客户端程序。它负责：

1. 向服务端发送上线信息和定时回连。
2. 接收服务端下发的任务。
3. 在 Windows 中执行任务。
4. 把任务结果打包后发回服务端。

本轮 Agent 的 Windows 实现主要位于：

[Windows Agent 源码目录](AdaptixServer/extenders/direct_https_agent/src_beacon)

### 3.2 什么是服务端插件

服务端插件运行在 Adaptix 服务端侧。它负责把界面上的按钮和参数转换成 Agent 能理解的二进制任务，也负责把 Agent 返回的二进制结果转换成界面能显示的文本、路径、文件列表或传输状态。

本轮服务端插件主要使用 Go 编写，核心文件是：

[pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go)

可以把它看作一个翻译层：

~~~text
界面中的“执行 cmd”
        |
        v
Go 插件把它翻译成 command ID 和参数
        |
        v
Windows Agent 执行进程
        |
        v
Go 插件把结果翻译成界面任务结果
~~~

### 3.3 什么是 WPP 和 WPS

在本次靶机环境中，wpp.exe 和 wps.exe 是需要重点验证的 Windows 主宿主进程名称。它们是实际承载 Agent 的主运行环境。

早期版本在插件型 WPS 会话中执行命令相对顺利，但主 wpp.exe / wps.exe 的子进程启动路径受到宿主进程环境、继承句柄和 Windows job 限制影响，CreateProcess 相关调用会返回 ACCESS_DENIED。

因此本轮的关键目标不是只证明 Agent 可以上线，而是证明下面这条完整链路可以运行：

~~~text
主 wpp.exe / 主 wps.exe
        |
        v
Agent 接收任务
        |
        v
Agent 创建 cmd.exe / powershell.exe
        |
        v
输出回到服务端和界面
~~~

### 3.4 什么是回连

Agent 按 profile 中的时间配置定期向服务端发起 HTTPS 请求。这些请求叫回连或心跳。

当前 profile 的主要参数是：

- listener：HTTPS_LISTENER
- sleep：10s
- jitter：0
- beat dialect：2
- connector：lite WinINet

本轮的存活标准是：在 720 秒监视期间，WPP 和 WPS 两个宿主都达到至少 6 次回连，并且进程保持 Responding=True。

## 4. 先理解几个专业词

| 术语 | 中文解释 | 本轮对应内容 |
|---|---|---|
| Agent | 运行在靶机上的客户端程序 | Windows C++ Agent |
| 服务端插件 | 把界面任务翻译成 Agent 协议的模块 | Go direct_https extender |
| listener | 服务端接收 Agent HTTPS 请求的监听器 | HTTPS_LISTENER |
| profile | 描述通信和构建参数的配置 | x64、sleep、jitter、connector |
| task | 一次用户操作 | 一次 cmd、一次 ls 或一次上传 |
| job | Agent 内部跟踪 task 的运行记录 | 保存进程、句柄、输出和完成状态 |
| command ID | 任务类型编号 | COMMAND_DISKS 等常量 |
| opcode/action ID | 协议中表示动作的编号 | native task record 中的动作编号 |
| frame | 一段带有标识、长度和内容的协议帧 | LPT4、LPR4 |
| section | 帧内部的一段分区数据 | task section、result section |
| envelope | 对任务或结果的外层封装 | task/result bundle |
| pipe | Windows 进程间传递数据的管道 | 捕获 stdout/stderr |
| handle | Windows 对文件、进程、管道等对象的引用 | 管道句柄、文件句柄、进程句柄 |
| job object | Windows 用来管理一组进程的对象 | 可能限制子进程脱离或继承句柄 |
| breakaway | 让子进程从父进程 job 管理关系中脱离 | CREATE_BREAKAWAY_FROM_JOB |
| token | Windows 身份和权限上下文 | CreateProcessAsUserA 等路径使用 |
| fallback | 后备路径 | 文件输出后备路径 |
| CRUD | 创建、读取、更新、删除 | mkdir、ls、cat、cp、mv、rm |
| static scan | 静态扫描 | 扫描磁盘上的文件 |
| memory scan | 内存扫描 | 扫描运行中的进程内存 |
| Qscan | Kaspersky 的系统扫描任务 | 记录处理、检测、错误数量 |
| SHA-256 | 文件内容指纹算法 | 比较上传前后或下载前后是否同一内容 |

## 5. 总体架构：数据怎样流动

最终版本保留了 Go 服务端插件、Windows C++ Agent、profile DLL、WPS proxy 和 runtime plugin 之间的边界。

~~~text
Adaptix 界面
    |
    | 用户选择命令和参数
    v
Go direct_https 服务端插件
    |
    | CreateCommand：创建任务
    | PackTasks：打包任务
    v
LPT4/schema4 任务帧
    |
    | HTTPS + 现有加密和封装
    v
Windows direct_https Agent
    |
    | Commander：识别命令并执行
    | JobsController：跟踪 job 和输出
    v
Windows 文件、进程或磁盘接口
    |
    | LPR4/native result bundle
    | 或 legacy result fallback
    v
Go ProcessData：解析结果
    |
    v
Adaptix 界面显示任务结果
~~~

这套结构的重点是：命令执行方式可以在 Agent 内部增强，服务端和界面仍然使用原有任务编号、结果字段和完成状态。

## 6. 用一次 cmd 任务说明完整过程

下面以界面执行一条简单 cmd 命令为例。

### 第一步：界面创建任务

用户在界面中输入命令，服务端插件得到命令名称、参数和目标 Agent 标识。

### 第二步：Go 插件转换参数

CreateCommand 将命令转换成类似这样的内部结构：

~~~text
command ID = COMMAND_PS_RUN
程序 = cmd.exe
参数 = /c <测试命令>
是否需要输出 = true
~~~

参数会按照 Agent 当前代码页转换成 Windows 侧字节，命令的参数顺序保持既有约定。

### 第三步：Go 插件打包任务

PackTasks 将任务放入 LPT4/schema4 任务帧。任务帧中包含任务编号、动作编号和参数字节。

任务编号很重要，因为 Agent 后面生成输出文件时会使用它：

~~~text
C:\Users\Public\direct-https-job-<taskId>.out
~~~

这样不同任务的输出文件可以区分，job 收尾时也可以准确清理。

### 第四步：Agent 回连并取到任务

Agent 按 sleep 配置发起 HTTPS 回连，服务端在响应中放入任务帧。Agent 解密并识别 LPT4，再按 section 长度取出任务记录。

### 第五步：Commander 尝试创建进程

Agent 进入 CmdPsRun，先尝试普通的 stdout/stderr 管道路径。如果主 WPP/WPS 的宿主环境允许，这条路径直接完成。

如果普通路径受到句柄、job 或权限上下文影响，Agent 继续尝试：

1. 显式继承句柄和 handle list。
2. CREATE_BREAKAWAY_FROM_JOB。
3. CreateProcessAsUserA。
4. CreateProcessWithTokenW。
5. native process parameter 路径。
6. shell broker 路径。
7. 文件输出后备路径。

### 第六步：文件输出后备路径

文件后备路径会把命令行变成带有输出重定向的形式：

~~~text
原命令
    |
    v
原命令 > "C:\Users\Public\direct-https-job-<taskId>.out" 2>&1
~~~

其中：

- > 表示把标准输出写入文件。
- 2>&1 表示把标准错误也合并到同一个文件。
- 2>&1 很重要，因为错误信息也需要返回到界面。

这条路径使用普通文件，而不是把输出直接绑定到主宿主的继承管道上，因此可以绕开主宿主句柄继承差异。

### 第七步：读取输出

JobsController 周期性查看输出文件。文件在第一次查看时暂时为空，并不等于命令已经失败；Agent 会等待进程状态，并在进程退出后再执行一次最终读取。

这次最终读取叫作最终 drain，作用是拿到命令结束前最后写入的那一小段输出。

### 第八步：返回结果和清理

Agent 将文本放入 LPR4/native result bundle 或兼容结果 body，服务端 ProcessData 解析后更新界面任务状态。

随后 Agent：

1. 关闭进程和文件句柄。
2. 释放命令行缓冲区。
3. 删除 direct-https-job-<taskId>.out。
4. 将任务标记为完成或错误。

靶机验证的重点就是：界面看到正确输出、进程保持响应、远程临时文件最终为空。

## 7. Go 服务端插件做了什么

文件：[pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go)

### 7.1 命令创建

现有的 CreateCommand 结构继续使用原有参数名、参数顺序和 command ID。这样 UI 的命令按钮、服务端 task 表和 Agent handler 可以继续对齐。

本轮补齐了 disks：

~~~text
disks -> COMMAND_DISKS -> native action selfC2ActionDisks
~~~

cmd 和 PowerShell 继续通过已有的进程执行命令编号进入 C++ Agent。

### 7.2 结果解析

ProcessData 根据 command ID 选择解析方式：

- 文本命令解析任务文本和完成状态。
- pwd、cd、cat 解析路径或文件内容。
- ls 解析文件列表。
- disks 解析成功位、错误码、盘符数量、盘符和驱动器类型。
- 上传和下载解析传输任务状态。

disks 的返回结果不是服务端预先写死的，而是根据靶机 Agent 返回的盘符数量循环读取。

### 7.3 packed 参数尾部处理

任务打包和解包时，字节数组可能带有对齐用的尾部 NUL。该 NUL 如果直接进入命令行，就可能被 Windows 侧当作命令参数的一部分。

本轮在命令行构造之前清理 packed 参数尾部 NUL，保持命令行内容与用户输入一致。

### 7.4 协议测试

文件：[pl_protocol_test.go](AdaptixServer/extenders/direct_https_agent/pl_protocol_test.go)

测试覆盖：

- LPT4 任务帧编码和解码。
- LPR4 结果 bundle。
- native task record。
- section/TLV 长度边界。
- legacy 兼容结果路径。
- native result field 的文本和路径数据。

direct_https_agent module 使用 Go 1.25.4 执行 go test ./...，结果通过。

## 8. Windows C++ Agent 做了什么

### 8.1 Commander.cpp：负责执行命令

文件：[Commander.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Commander.cpp)

Commander 可以理解为 Agent 内部的命令总调度器。它根据 command ID 调用对应处理函数。

本轮重点修改了进程型命令的执行过程：

- 创建 stdout/stderr 管道。
- 设置父子进程之间的句柄关系。
- 记录 CreateProcessA 的原始错误码。
- 尝试 handle list。
- 尝试 job breakaway。
- 尝试 CreateProcessAsUserA。
- 尝试 CreateProcessWithTokenW。
- 尝试 native process parameter。
- 对 cmd.exe 和 PowerShell 分别构造适合的命令行。
- 进入文件输出后备路径。

为了方便定位，代码设置了内部诊断位，用于标记普通创建、breakaway、AsUser 和文件后备分支。诊断信息主要进入原始证据文件，现有服务端协议字段保持稳定。

### 8.2 JobsController.cpp：负责任务生命周期

文件：[JobsController.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/JobsController.cpp)

JobsController 负责一个任务从开始到结束的状态管理：

1. 保存进程句柄和输出句柄。
2. 周期性读取管道或后备文件。
3. 判断进程是否已经结束。
4. 在结束时执行最终 drain。
5. 组装任务结果。
6. 关闭句柄。
7. 删除临时输出文件。
8. 只结束一次任务状态。

本轮修复的关键点是区分两个状态：

~~~text
文件目前为空
进程已经退出并且文件读取完成
~~~

前者需要继续等待，后者才进入清理流程。

### 8.3 ApiLoader.cpp：负责寻找 Windows API

文件：[ApiLoader.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ApiLoader.cpp)

Agent 通过运行时 API 表取得函数地址。这样做的直接作用是把调用集中到 ApiWin、ApiNt 等结构中，C++ 代码可以统一判断某个 API 是否存在。

本轮确认和补齐了以下调用入口：

~~~text
CreateProcessA
CreateProcessAsUserA
CreateProcessWithTokenW
CreatePipe
CreateFileA
PeekNamedPipe
GetExitCodeProcess
WideCharToMultiByte
RtlCreateProcessParameters
NtOpenProcessToken
~~~

文件：[ApiLoader.h](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ApiLoader.h)

### 8.4 ntdll.h：声明 native 辅助接口

文件：[ntdll.h](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/ntdll.h)

它提供 RtlCreateProcessParameters、token 相关接口和 native 状态类型的声明，使 Agent 可以在普通 Win32 路径遇到主宿主限制时，使用另一组底层创建参数路径进行诊断和尝试。

### 8.5 utils.cpp：处理 PowerShell 编码

文件：[utils.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/utils.cpp)

Windows PowerShell 5.1 通过普通文件重定向输出时，常见格式是：

~~~text
UTF-16LE BOM + UTF-16LE 文本
~~~

而现有结果协议和界面显示路径使用 Agent 当前代码页字节。于是本轮增加了以下转换：

1. 检查文件开头是否存在 UTF-16LE BOM。
2. 按 UTF-16LE 读取字符。
3. 调用 WideCharToMultiByte 转换成当前 OEM code page。
4. 将转换后的内容放回已有结果 body。

因此 PowerShell 的标记文本、路径查询和错误文本可以与 cmd 输出统一显示。

## 9. 文件输出后备路径：为什么需要它

### 9.1 普通管道路径是什么

普通做法是 Agent 创建一个管道：

~~~text
cmd.exe stdout/stderr -> 管道 -> Agent 读取 -> 服务端
~~~

这条路径效率高，也容易得到实时输出，但它依赖多个 Windows 条件同时成立：

- 父进程允许创建子进程。
- stdout/stderr 句柄能正确继承。
- job object 允许子进程使用预期的生命周期。
- startup information 中的句柄配置符合主宿主环境。
- 当前 token 具备创建子进程所需的上下文。

主 WPP/WPS 的运行环境会让其中某一项条件失效，于是普通路径出现 ACCESS_DENIED 或输出丢失。

### 9.2 文件后备路径是什么

文件后备路径把数据流改成：

~~~text
cmd.exe / powershell.exe
        |
        | > output-file 2>&1
        v
C:\Users\Public\direct-https-job-<taskId>.out
        |
        v
Agent 读取文件
        |
        v
现有结果协议
~~~

它把“子进程输出怎样传给 Agent”从继承管道改成普通文件读写。任务编号负责区分文件，JobsController 负责最终关闭和删除。

### 9.3 文件后备路径的生命周期

| 阶段 | 动作 |
|---|---|
| 创建 | 按 taskId 生成文件名 |
| 启动 | 在命令末尾追加 > "file" 2>&1 |
| 读取 | Agent 周期性读取新写入内容 |
| 等待 | 文件为空但进程仍运行时继续等待 |
| 收尾 | 进程退出后执行最终 drain |
| 清理 | 关闭句柄、释放内存、删除文件 |
| 证据 | 远程查询 direct-https-job-*.out 应为空 |

## 10. 协议兼容：哪些东西保持稳定

本轮的原则是恢复功能时复用已有协议，而不是重新设计一套界面和 Agent 都需要重新适配的协议。

### 10.1 任务方向

任务从服务端到 Agent 主要经过：

~~~text
任务记录
  -> LPT4 task frame
  -> schema4 section
  -> native task record 或兼容 task body
  -> Windows command handler
~~~

### 10.2 结果方向

结果从 Agent 回到服务端主要经过：

~~~text
Windows command handler
  -> LPR4 result bundle 或兼容 result body
  -> section 解包
  -> command ID 对应的 ProcessData 分支
  -> Adaptix task 状态和显示内容
~~~

### 10.3 当前版本保留的内容

- 现有 task envelope schema。
- LPT4/schema4 section framing。
- native result bundle V4。
- legacy result fallback。
- 已有 command ID 和参数顺序。
- COMMAND_ERROR 的三字段响应布局。
- 任务完成、错误和重连后的状态语义。

disks 只使用现有命令编号和结果处理模式增加了一个能力；它的返回结构包含：

~~~text
taskId
commandId
success
driveCount
drive letter
drive type
~~~

## 11. 当前 14 项命令分别做什么

| 命令 | 初学者理解 | 实际检查 |
|---|---|---|
| hello | 最简单的连通性测试 | Agent 能上线并返回固定文本 |
| cmd | 执行 Windows 命令解释器 | 标记文本、身份和目录查询 |
| powershell | 执行 PowerShell 命令 | Write-Output、路径查询和编码 |
| pwd | 查看当前目录 | 返回当前工作目录 |
| cd | 切换当前目录 | 切换到 scratch 目录并回到 WPS 目录 |
| ls | 查看目录内容 | 查看 sentinel 文件和目录 |
| cat | 读取文件内容 | 读取上传的 marker 内容 |
| mkdir | 创建目录 | 创建唯一 scratch 目录 |
| rm | 删除文件或目录 | 删除源文件、移动后的文件和目录 |
| cp | 复制文件 | 复制 sentinel 文件并检查内容 |
| mv | 移动或重命名文件 | 移动复制后的文件并检查路径 |
| disks | 查看逻辑磁盘 | 比较 Agent 结果和 Win32_LogicalDisk |
| upload | 从服务端传文件到靶机 | 上传 49-byte marker |
| download | 从靶机取文件回服务端 | 下载并比较 SHA-256 |

文件回归的实际顺序可以理解为：

~~~text
创建 scratch
  -> mkdir
  -> upload marker
  -> ls / cat
  -> cp
  -> mv
  -> download
  -> SHA-256 比较
  -> rm 文件
  -> 删除 scratch
~~~

## 12. 构建做了什么

### 12.1 C++ 构建

对 Windows Agent 源码执行了 x64 和 x86 对象构建。x64 版本用于最终 WPP/WPS 运行验证，x86 对象用于确认源代码和构建配置在另一目标架构下保持可编译。

### 12.2 profile 和 cache

profile DLL 描述连接方式、sleep、jitter、listener 和相关构建开关。它被打包成 profile binary，再进入 cache.dat。

本轮沿用已经验证过的构建开关：

~~~text
DIRECT_HTTPS_LAZY_HTTP_SEND=1
DIRECT_HTTPS_LAZY_WININET_INIT=1
DIRECT_HTTPS_LITE_CONNECTOR=1
DIRECT_HTTPS_NO_API_HASHING=1
DIRECT_HTTPS_BEAT_DIALECT=2
~~~

### 12.3 WPS proxy 和 runtime plugin

最终包中的主要文件含义：

| 文件 | 作用 |
|---|---|
| cache.dat | profile/configuration 打包结果 |
| krpt.dll | WPS proxy 制品 |
| krpt.agent.dll | WPS proxy 对应的 Agent 制品 |
| agent_direct_https.so | Adaptix runtime plugin |
| direct_https_profile.x64.dll | x64 profile DLL |
| direct_https_profile.x64.bin | profile 的容器形式 |
| profile.bin | profile payload |
| build-logs/ | 构建、扫描和 Go 测试日志 |
| SHA256SUMS | 发布包文件完整性清单 |

最终包目录：

LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1

### 12.4 核心哈希

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| cache.dat | 79,896 | 5c89811ade759d5c1c6cc25f153357931f66320160da63e77c055c7d2193961b |
| krpt.dll | 50,688 | b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac |
| krpt.agent.dll | 50,688 | b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac |
| agent_direct_https.so | 5,555,176 | d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779 |
| direct_https_profile.x64.dll | 79,360 | 68a869ea61661679b80e7960e0d2ddcbef3c71e0fb9f7d59acbeb01af051860e |
| direct_https_profile.x64.bin | 79,360 | ddedc93991527f2c08a4bb57e934d3023fe095dd7ac13cae59ec13c84126c5c7 |
| profile.bin | 275 | a2ab53a8599ec53f841b29eda26b44ca454a577c63d295b0d019aa6f01544df9 |

## 13. 怎样进行真实验证

### 13.1 每轮验证的固定顺序

每个 release 候选都按以下顺序执行：

1. 检查源码差异和构建参数。
2. 执行 Go、C++ 和 Python 侧测试。
3. 生成 profile DLL、cache.dat、WPS proxy 和 runtime plugin。
4. 记录每个文件的大小和 SHA-256。
5. 停止旧 WPP/WPS 会话并备份靶机文件。
6. 部署新候选。
7. 静态扫描 cache.dat、krpt.dll、krpt.agent.dll。
8. 执行 Scan_System_Memory。
9. 等待已有扫描任务结束，再启动新的 Scan_Qscan。
10. 启动 720 秒回连监视。
11. 在主 WPP 上执行完整矩阵。
12. 在主 WPS 上执行等价完整矩阵。
13. 执行 F0、disks、文件 CRUD 和 upload/download。
14. 检查进程响应、任务结果和远程文件清理。
15. 保存原始日志、JSON 结果和最终结论。

### 13.2 Kaspersky 三层门禁分别测什么

#### 静态扫描

静态扫描读取磁盘上的文件内容，检查制品本身是否被识别。它回答的是：

~~~text
这个文件放在磁盘上时，扫描结果是什么？
~~~

本轮扫描的三个对象是：

~~~text
cache.dat
krpt.dll
krpt.agent.dll
~~~

#### 系统内存扫描

系统内存扫描观察已经运行起来的进程和加载内容。它回答的是：

~~~text
文件已经被部署并运行后，内存中的状态是什么？
~~~

#### Qscan

Qscan 是更大范围的系统扫描任务。每轮都使用新任务，并单独记录：

- 任务是否进入 completed。
- processed 数量。
- detected 数量。
- errors 数量。
- 命令返回码。

历史任务的统计不会代替当前 release 的新鲜 Qscan 结果。

## 14. 三轮真实部署结果

### 14.1 release-run-2b

- 部署时间：18:37:29 - 18:49:45
- WPP/WPS 回连：65/65
- WPP/WPS 完整矩阵：17/17
- F0 主命令检查：10/10
- disks：WPP/WPS 两个角色通过
- Qscan：3548 / 0 / 0
- 上传下载：哈希匹配
- 远程 scratch 和 direct-https-job-*.out：清理完成

原始报告：[release-run-2b/RESULT.md](LOCAL_CANDIDATE_ROOT/release-run-2b/RESULT.md)

### 14.2 release-run-3

- 部署时间：19:03:30 - 19:16:37
- WPP/WPS 回连：60/64
- WPP/WPS 完整矩阵：17/17
- F0 主命令检查：10/10
- disks：WPP/WPS 两个角色通过
- Qscan：3572 / 0 / 0
- 上传下载：哈希匹配
- 远程 scratch 和 direct-https-job-*.out：清理完成

原始报告：[release-run-3/RESULT.md](LOCAL_CANDIDATE_ROOT/release-run-3/RESULT.md)

### 14.3 release-run-4

- 部署时间：19:26:09 - 19:38:43
- WPP/WPS 回连：65/65
- WPP/WPS 完整矩阵：17/17
- F0 主命令检查：10/10
- disks：WPP/WPS 两个角色通过
- Qscan：3572 / 0 / 0
- 上传下载：哈希匹配
- 远程 scratch 和 direct-https-job-*.out：清理完成

原始报告：[release-run-4/RESULT.md](LOCAL_CANDIDATE_ROOT/release-run-4/RESULT.md)

最终靶机快照：[release-survival-final.txt](LOCAL_CANDIDATE_ROOT/release-survival-final.txt)

快照中可以看到：

- wpp.exe 的 Responding=True。
- 观测到的 wps.exe 进程均为 Responding=True。
- SCRATCH 标记后没有残留 scratch 路径。
- JOB_FILES 标记后没有残留输出文件路径。

## 15. 文件传输为什么要做哈希核对

只看到上传任务显示“完成”，还不足以证明文件内容正确。文件传输需要至少检查三件事：

1. 目标文件确实存在。
2. 文件大小符合预期。
3. 文件内容与源文件一致。

因此本轮使用固定 marker 文件，并在下载回收后计算 SHA-256：

~~~text
源文件 -> upload -> 靶机文件
靶机文件 -> download -> 本地回收文件
本地回收文件 SHA-256 与预期值比较
~~~

三轮中 WPP 和 WPS 的 49-byte marker 均完成匹配。随后删除远程源文件、移动后的文件、scratch 目录和本地下载临时文件。

## 16. GitHub 研究怎样影响架构

本轮参考了四类公开项目的组织方式。研究结果用于“怎样划分模块、怎样记录证据”，代码仍然使用当前项目已有的协议和构建链。

- [AdaptixC2](https://github.com/Adaptix-Framework/AdaptixC2)：参考 listener、Agent、任务状态和 jobs 之间的边界。
- [MythicAgents/Xenon](https://github.com/MythicAgents/Xenon)：参考按能力组织命令和 profile 的方式。
- [RedEdr](https://github.com/dobin/RedEdr)：参考把进程、线程、镜像、内存区域和调用链作为不同观察面。
- [CAPEv2](https://github.com/kevoreilly/CAPEv2)：参考把动态行为、网络、扫描和内存证据分层保存。

本轮具体落地成三点：

1. 命令能力按 F0/F1/F2/F3 分阶段恢复。
2. 每个候选保存源码版本、制品哈希、扫描日志、功能 JSON 和清理证据。
3. 最终 release 与失败诊断 run 分开，成功统计只使用通过全部门禁的新鲜部署。

## 17. 测试结果和当前边界

### 17.1 已完成的检查

- direct_https_agent Go module：Go 1.25.4 下 go test ./... 通过。
- AdaptixServer 根 module：go test -vet=off ./... 通过。
- C++ x64/x86 构建通过。
- Python 功能脚本编译通过。
- 发布脚本 bash -n 通过。
- 发布包 sha256sum -c SHA256SUMS 通过。
- 源码目录 git diff --check 通过。
- 三轮 Kaspersky 静态、内存、Qscan 门禁通过。
- 三轮 WPP/WPS 真实功能矩阵通过。

### 17.2 根 module 的默认 vet 诊断

AdaptixServer 根 module 直接执行 go test ./... 时，Go vet 会报告既有的动态格式串调用，涉及 logs.* 调用点。这些诊断来自根 module 的原有工程代码，与本轮 direct_https Agent 功能恢复没有直接关系。

对应日志：

- build-logs/go-test-AdaptixServer-1.25.4.log
- build-logs/go-test-AdaptixServer-vet-off-1.25.4.log
- build-logs/go-test-direct-https-agent-1.25.4.log

### 17.3 当前 release 未纳入的能力

以下能力按计划留到后续独立候选：

- jobs kill
- terminate
- save memory
- download pause
- download resume
- download cancel

这样当前 v1 的验证范围集中在已经注册且完成真实主宿主回归的 14 项命令面。

### 17.4 失败诊断记录

release-run-1 和第一次 release-run-2 保留在候选目录中，用来记录扫描任务占用和异步退出码采集等问题。最终成功次数只使用：

~~~text
release-run-2b
release-run-3
release-run-4
~~~

## 18. 发布包和文件位置

最终发布包：

[release-wpp-functional-v1](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/MANIFEST.md)

完整候选目录：

LOCAL_CANDIDATE_ROOT

关键证据：

- [最终结果报告](LOCAL_CANDIDATE_ROOT/RESULT.md)
- [最终存活和清理快照](LOCAL_CANDIDATE_ROOT/release-survival-final.txt)
- [run-2b 部署日志](LOCAL_CANDIDATE_ROOT/release-run-2b/deploy-scan.log)
- [run-3 部署日志](LOCAL_CANDIDATE_ROOT/release-run-3/deploy-scan.log)
- [run-4 部署日志](LOCAL_CANDIDATE_ROOT/release-run-4/deploy-scan.log)
- [发布包 SHA256SUMS](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/SHA256SUMS)
- [阶段总报告](LOCAL_STAGE_SUMMARY)

## 19. 复核命令

下面的命令用于查看源码 tag 和发布包完整性：

~~~bash
cd LOCAL_ADAPTIXC2_ROOT
git show --stat 72e54efee51ee70445344a81c4580142a505b0e2
git rev-list -n 1 release-wpp-functional-v1

cd LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1
sha256sum -c SHA256SUMS
bash -n scan-and-deploy.sh
~~~

这份文档解释“做了什么”和“为什么这样做”；原始扫描输出、功能 JSON、回连 monitor、远程清理记录、构建日志和失败诊断日志继续保存在候选目录中。
