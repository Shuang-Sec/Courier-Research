# Courier Research

Adaptix `direct_https` agent 的加载与通信研究项目：涵盖 agent 结构分析、内存加载（profile-only loader）、加密容器、通信协议、宿主集成与投放入口实验。本仓库提供可追溯、可阅读、可二次整理的源码与文档基线。

## 研究主题

- `direct_https` agent 结构分析
- 构建链 / 生成链排查
- 初始化 / 通信路径定位
- MemoryModulePP_Lite 实验
- `profile-only loader` 设计与实现
- `DHPL1 -> AES-GCM -> DHPLE2(PBKDF2 + salt + AES-GCM)` 容器演进
- PE header 痕迹处理与内存形态验证
- WPP/WPS `krpt.dll` 代理层、`cache.dat` 加密容器和 direct_https Agent 回连链路
- AcroTray 四文件宿主实验（宿主 + loader 入口 DLL + 原始 DLL + 加密 profile 容器）
- direct_https 通信协议 v6/v7 与运行期 sleep/jitter 命令
- PDF 投放入口实验（URI 动作引导下载 / PDF 尾部内嵌本地提取 / 快捷方式形态交付）

---

## 1. 仓库内容

本仓库以源码与研究文档为核心，不收录运行时产物。

**包含**

- 关键源码
- 研究脚本
- 设计文档与实验摘要

**不包含**

- 运行时构建产物（`dist/`）
- 完整实验证据树
- Windows 测试样本
- 本地构建中间件
- API 凭据、主机助手、私钥与网络拓扑信息

---

## 2. 目录结构

### `AdaptixServer/extenders/direct_https_agent/`
`direct_https` agent 的主要源码：

- Go 插件层
- beacon 源码
- command / packer / connector 逻辑
- 生成 payload 时需要的配置与模板

### `research/memory-loader-lab/`
内存加载相关研究：

- MemoryModule / MemoryModulePP_Lite 实验
- profile-only loader 源码
- 容器打包脚本
- DLL payload 构建辅助脚本
- 第三方 loader 裁剪版

### `research/wps-krpt-proxy/`
WPP/WPS 宿主代理层：

- `krpt.dll` 入口包装（WPS 实际加载的代理模块）
- 原始 `krpt.dll` 导出 forwarder 生成
- `DllMain -> loader thread -> dhpl_loader_main` 调用链
- 带诊断和精简诊断两套构建入口

### `scripts/`
实验辅助脚本：

- 构建与重新生成
- 样本发布 / 启动
- callback / hello / 命令矩阵验证
- 静态差分与内存扫描辅助

### `docs/`
研究文档与实验记录：

- `research-summary.md`
- `build-run-overview.md`
- `evidence-summary.tsv`
- `sanitization-notes.md`
- `source-baseline.md`
- `repo-map.md`
- `build-matrix.md`
- `binary-release-policy.md`
- `research-roadmap.md`
- `experiment-template.md`
- `decision-log.md`
- `evidence/2026-07-21-wpp-wps-f0-ps-encoding/`
  - 三次独立部署的最终结果摘要
  - WPS DLL 到 Agent 的逐函数说明
  - 构建产物 SHA-256 和 Kaspersky 门禁摘要

---

## 2.1 长期维护文档

为支持长期维护，仓库包含以下文档：

| 文件 | 用途 |
|---|---|
| `CHANGELOG.md` | 版本变更与仓库维护记录 |
| `docs/repo-map.md` | 目录与关键文件定位 |
| `docs/build-matrix.md` | 代码层级变更与重编 / 重启 / 重新生成的对应关系 |
| `docs/binary-release-policy.md` | release 内容范围 |
| `docs/research-roadmap.md` | 研究路线规划 |
| `docs/experiment-template.md` | 实验记录模板 |
| `docs/decision-log.md` | 关键设计决策与依据 |

---

## 3. 研究进展

### 3.1 WPP/WPS 主宿主基线（当前代码版本）

这一版的研究重点主要有 5 个：

1. **direct_https 的源码与运行链已经被拆清楚**
   - 包括 agent 初始化、命令面、通信面、构建链和重新生成流程。

2. **内存加载链已经从“完整 DLL 原样加密”演进到“最小元数据容器 + 专用 loader”**
   - 即先做离线提取，再在运行时按最小必要元数据完成映射。

3. **外层容器保护已经从简单 XOR 演进到更正式的密钥派生与认证加密方案**
   - 当前代码版本采用 `PBKDF2 + salt + AES-256-GCM` 这条线。

4. **已经把 PE header 痕迹问题从“看见问题”推进到了“结构性处理”阶段**
   - 仓库中保留了对应源码、脚本和文档说明。

5. **WPP/WPS 主宿主的功能版候选已经完成 F0-F3 验证**
   - 最新候选覆盖当前注册的 14 项命令。
   - 三次独立新鲜部署均完成 WPP/WPS 主宿主矩阵、文件传输和 Kaspersky 门禁。
   - 详细证据入口：[2026-07-21 WPP/WPS F0-F3 evidence](docs/evidence/2026-07-21-wpp-wps-f0-ps-encoding/README.md)

### 3.2 AcroTray 四文件宿主与协议演进（2026-08 进展）

在 WPP/WPS 基线之外，研究主线继续推进到新的宿主与通信层：

1. **AcroTray 四文件宿主**：以带签名的轻量宿主 + DLL 侧加载组合作为新入口——宿主、loader 入口 DLL、原始 DLL 备份与加密 profile 容器（`cache.dat`）四文件即完整运行包；运行期复用 `profile-only loader` 的既有链路（`DHPLE2 -> PBKDF2 -> AES-256-GCM -> DHPL1 -> section 映射 -> RunAgentDll`）。
2. **协议 v6/v7 工程化**：把心跳、任务、结果整理为带显式 schema、长度、record 边界、CRC32 与消息关联（message_id / reply_to）的版本化帧；统一帧头与校验规则；保留旧版本回退；命令语义层保持稳定，14 项功能全量回归。
3. **运行期 sleep/jitter 命令**：恢复运行期可调的 sleep 命令，与 profile 中 sleep/jitter 默认值配合，高频交互与低频静默场景可按需切换。
4. **远端运行面迁移**：Teamserver 运行面按「本机源码构建 + 远端仅部署编译产物」的边界部署到远端 Linux 主机，Agent 直连远端监听器；源码、构建脚本与 Git 历史全部保留在本机。

### 3.3 PDF 投放入口实验（2026-08 进展）

- 以 PDF 文档的 URI 动作作为 agent 四文件包的获取入口；PDF 显示内容与触发逻辑分离——显示内容可替换为任意正常文档页面，触发逻辑保持不变。
- 入口文件的下载服务可部署在任意可达的 HTTP stage；后续演进到「入口文件直接内嵌 PDF 尾部、打开后本地提取」的单文件形态，以及「外观为 PDF 的快捷方式 + 隐藏载荷目录」的交付形态。
- 靶机侧链路按「下载 → 四文件哈希校验 → 部署 → 宿主启动 → 回连」分层验证，把“下载成功”与“上线成功”分开取证。
- 验证：真实靶机上完成 14 项功能矩阵回归与 Kaspersky / Windows Defender 门禁。

### 3.4 代码同步状态与后续计划

- 当前仓库中的源码对应 WPP/WPS 基线版本；上文 AcroTray 宿主、协议 v7、sleep 命令与 PDF 入口的实现将随后续版本源码发布同步更新。
- 实验相关细节（网络地址、凭据、检测特征、测试样本）不属于本仓库内容；复现所需的环境信息以占位方式提供（见第 5 节）。
- 后续计划：同步新源码基线，并相应更新 `docs/research-summary.md`、`docs/repo-map.md` 与 `docs/research-roadmap.md`。

---

## 4. 推荐阅读顺序

推荐阅读顺序如下：

1. `docs/research-summary.md`
2. `docs/repo-map.md`
3. `docs/build-run-overview.md`
4. `docs/build-matrix.md`
5. `docs/research-roadmap.md`
6. `docs/decision-log.md`
7. `docs/binary-release-policy.md`
8. `docs/evidence-summary.tsv`
9. `docs/source-baseline.md`
10. `docs/experiment-template.md`
11. `research/memory-loader-lab/README.md`
12. `research/wps-krpt-proxy/README.md`
13. `docs/evidence/2026-07-21-wpp-wps-f0-ps-encoding/README.md`

读完上述文档后，再回头看源码，会更容易理解它们在整条链路里的位置。

---

## 5. 环境准备

实验脚本中的环境相关配置使用占位值，直接运行前需要替换为实际环境信息：

- Adaptix API 地址 / 用户名 / 密码
- Windows 测试机地址与启动链路
- 发布目录 / HTTP 文件服务目录
- SSH helper / WMI / Scheduled Task 相关本地路径
- passphrase / key / 运行参数

可以先参考：

- `.adaptix_api.env.example`
- `docs/sanitization-notes.md`
- `scripts/` 下各脚本顶部注释

---

## 6. Release 策略

release 内容范围：

- 源码标签
- release notes
- 非可执行的补充资料

默认**不上传**以下内容：

- `*.exe`
- `*.dll`
- `*.bin`
- `*.dat`
- `*.o`
- `*.a`
- 本地构建日志和环境绑定样本

本仓库定位为研究归档、代码回溯与文档基线，不作为可直接运行的本地环境镜像。

---

## 7. 版本基线

本仓库版本对应的基线信息见：

- `docs/source-baseline.md`
- `CHANGELOG.md`
- `docs/decision-log.md`

其中记录了：

- 原始本地分支
- 本地基线 tag
- 版本同步策略
- 对应的近期关键 commit 摘要
- 仓库维护记录
- 关键长期决策
