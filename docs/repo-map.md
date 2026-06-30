# 仓库地图（repo map）

这份文档的目标很简单：

- **我下次回来时，能迅速找到关键文件**
- **我看见一个文件时，知道它属于哪一层**
- **我想改某个行为时，知道应该先从哪几个文件下手**

---

## 1. 仓库总览

当前私有仓库主要由 4 个部分组成：

| 目录 | 作用 | 你通常在什么时候看它 |
|---|---|---|
| `AdaptixServer/extenders/direct_https_agent/` | direct_https agent 主源码 | 想看 agent 行为、命令面、通信面、构建面 |
| `research/memory-loader-lab/` | 内存加载与容器研究代码 | 想看 loader、容器、手动映射、PE header 处理 |
| `scripts/` | 自动化辅助脚本 | 想快速复现实验、构建、生成、验证 |
| `docs/` | 去敏后的说明文档 | 想先搞清思路、路径、阶段结论 |

---

## 2. 最重要的入口文件

如果你时间很少，只先看这些：

| 文件 | 为什么最值得先看 |
|---|---|
| `README.md` | 仓库总体定位和阅读顺序 |
| `docs/research-summary.md` | 近期研究主线总结 |
| `docs/build-run-overview.md` | 从源码到运行的简化链路 |
| `docs/build-matrix.md` | 改完代码后到底要不要重编 / 重启 / 重新生成 |
| `docs/binary-release-policy.md` | 哪些产物可以放 release，哪些不要放 |

---

## 3. direct_https agent 代码地图

目录：

```text
AdaptixServer/extenders/direct_https_agent/
```

### 3.1 Go 插件层

| 文件 | 作用 |
|---|---|
| `pl_main.go` | 插件主逻辑；命令注册、profile 生成、payload 生成的关键入口 |
| `pl_packer.go` | 与打包/解包相关的 Go 层辅助逻辑 |
| `pl_utils.go` | 通用工具函数，比如时间、编码、打包辅助等 |
| `config.yaml` | 插件加载与配置说明 |
| `ax_config.axs` | Adaptix 侧 UI / 命令配置脚本 |

### 3.2 beacon / C++ 层

目录：

```text
AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/
```

最常看的文件：

| 文件 | 作用 |
|---|---|
| `MainAgent.cpp` | agent 主循环、初始化、probe、通信相关关键行为 |
| `ApiLoader.cpp` | 动态解析 WinAPI 的逻辑 |
| `ConnectorHTTP.cpp` | HTTP/HTTPS 通信实现 |
| `Commander.cpp` | 命令执行、文件功能、常见 command handler |
| `AgentConfig.cpp` | 解析 profile / 配置 |
| `Packer.cpp` | C++ 侧 pack/unpack 逻辑 |
| `Downloader.cpp` | 文件下载相关逻辑 |
| `MemorySaver.cpp` | 文件上传过程中临时缓存逻辑 |

### 3.3 如果我想查某类行为，从哪里开始

| 想看什么 | 先看哪里 |
|---|---|
| agent 初始化 | `MainAgent.cpp`、`ApiLoader.cpp` |
| 网络请求 / WinINet | `ConnectorHTTP.cpp`、`MainAgent.cpp` |
| PowerShell / cmd / 文件命令 | `Commander.cpp` |
| listener/profile 是怎么打进去的 | `pl_main.go`、`AgentConfig.cpp` |
| payload 是怎么生成出来的 | `pl_main.go`、`src_beacon/Makefile` |

---

## 4. memory-loader-lab 代码地图

目录：

```text
research/memory-loader-lab/
```

### 4.1 最重要的文件

| 文件 | 作用 |
|---|---|
| `src/loader_profile_only.c` | 当前 profile-only loader 主实现 |
| `pack_profile_container.py` | 把 DLL 处理成专用容器的脚本 |
| `build_direct_https_profile_dll.py` | 构建当前 DLL payload 的脚本 |
| `Makefile` | loader / 实验产物的构建入口 |
| `README.md` | memory-loader-lab 的子说明文档 |

### 4.2 历史/对照实验文件

| 文件 | 作用 |
|---|---|
| `src/loader_agentdll_mmpp_lite.c` | 较早的 MemoryModulePP_Lite 版 loader |
| `src/loader_agentdll_quiet.c` | 较早的 quiet loader 对照 |
| `src/loader_agentdll_encrypted.c` | 较早的加密版 loader 实验 |
| `src/loader_plain.c` | 最小 baseline |
| `src/loader_encrypted.c` | 最小加密 baseline |
| `src/hello_payload.c` | 最小无害 hello payload |

### 4.3 第三方代码区

| 目录 | 作用 |
|---|---|
| `third_party/MemoryModule/` | MemoryModule 对照实现 |
| `third_party/MemoryModulePP_Lite/` | 你当前实验中更重要的轻量实现参考 |

---

## 5. scripts 地图

目录：

```text
scripts/
```

| 文件 | 作用 | 典型用途 |
|---|---|---|
| `regenerate-direct-https-agent.sh` | 一键重建 + 同步 + 重启 + 重新生成 payload | 改 direct_https 插件后生成新 agent |
| `run-mmpp-powershell-loader-test.sh` | 自动化 Windows 启动 / 轮询 callback / hello | 跑 memory loader 测试 |
| `run-profile-only-loader-test.sh` | 跑 profile-only loader 版本 | 当前 profile-only 链路测试 |
| `baseline-direct-https-api.py` | 辅助校验 direct_https API/命令面 | 快速确认 C2 侧基础行为 |
| `verify-direct-https-command-surface.py` | 命令矩阵辅助验证 | 检查命令面是否完整 |
| `diff-profile-loader-static.py` | 静态差分辅助 | 比不同 loader 产物 |
| `monitor-direct-https-survival.py` | 存活监控辅助 | 长时间跟踪 agent 状态 |
| `http-request-capture-server.py` | HTTP request capture | 看请求内容和发送时机 |
| `windows-scan-process-pe-memory.ps1` | Windows 进程内存 PE 痕迹扫描 | 看 MZ/PE、header、权限等 |

---

## 6. docs 地图

目录：

```text
docs/
```

| 文件 | 作用 |
|---|---|
| `research-summary.md` | 总体研究脉络摘要 |
| `build-run-overview.md` | 源码 -> 构建 -> 启动 的简化说明 |
| `evidence-summary.tsv` | 去敏后的关键证据摘要 |
| `sanitization-notes.md` | 为什么这个仓库被这样去敏 |
| `source-baseline.md` | 本地基线与导出关系 |
| `release-notes-baseline-2026-06-30.md` | 当前 release 的正式说明 |
| `build-matrix.md` | 改完某层代码后要做哪些动作 |
| `binary-release-policy.md` | release 资产的准入/禁入规则 |

---

## 7. 快速定位：我应该看哪一层

### 情况 A：我怀疑是 agent 本身逻辑有问题

先看：

- `AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp`
- `ConnectorHTTP.cpp`
- `Commander.cpp`

### 情况 B：我怀疑是 payload 重新生成链路出了问题

先看：

- `docs/build-matrix.md`
- `scripts/regenerate-direct-https-agent.sh`
- `pl_main.go`

### 情况 C：我怀疑是 loader / 容器这条线的问题

先看：

- `research/memory-loader-lab/src/loader_profile_only.c`
- `research/memory-loader-lab/pack_profile_container.py`
- `research/memory-loader-lab/build_direct_https_profile_dll.py`

### 情况 D：我想知道某个二进制能不能放 release

先看：

- `docs/binary-release-policy.md`

---

## 8. 维护建议

以后如果仓库继续长大，建议继续保持一个原则：

- **源码看目录**
- **流程看矩阵**
- **阶段看 changelog**
- **发布看 release policy**

这样仓库就不会变成“文件很多，但回头看不懂”的状态。

