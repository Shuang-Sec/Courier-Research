# WPP/WPS F0-F3 最终候选证据索引

## 候选身份

| 字段 | 值 |
|---|---|
| 候选 | `wpp-wps-f0-ps-encoding-20260721-165405` |
| 本地源码提交 | `72e54efee51ee70445344a81c4580142a505b0e2` |
| 本地标签 | `release-wpp-functional-v1` |
| profile | x64、sleep 10s、jitter 0、beat dialect 2、lite WinINet |
| 功能范围 | `hello`、`cmd`、`powershell`、`pwd`、`cd`、`ls`、`cat`、`mkdir`、`rm`、`cp`、`mv`、`disks`、`upload`、`download` |

## 结果结论

同一批候选文件完成三次独立新鲜部署。每次都完成 WPP/WPS 主宿主回连、功能矩阵、文件传输和 Kaspersky 三层门禁。

| 运行 | 新鲜 Qscan | 回连监视 | WPP/WPS 矩阵 | F0 主命令 | disks | 传输 | 结论 |
|---|---:|---:|---:|---:|---:|---|---|
| `release-run-2b` | 3548 / 0 / 0 | 65 / 65 | 17/17 | 10/10 | 2/2 | SHA-256 匹配 | PASS |
| `release-run-3` | 3572 / 0 / 0 | 60 / 64 | 17/17 | 10/10 | 2/2 | SHA-256 匹配 | PASS |
| `release-run-4` | 3572 / 0 / 0 | 65 / 65 | 17/17 | 10/10 | 2/2 | SHA-256 匹配 | PASS |

Qscan 的三个数字依次表示：`processed / detected / errors`。

## 关键实现

- `Commander.cpp` 增加主 WPP/WPS 下的文件输出后备路径。
- `JobsController.cpp` 在完成前做最终输出 drain，再关闭 job 和临时文件句柄。
- PowerShell 文件输出按 UTF-16LE 识别并转换到 Agent OEM code page。
- Go 侧保留 LPT4/schema4、native result bundle V4 和 legacy fallback。
- `disks` 返回靶机实际可见的驱动器和类型。
- 文件回归覆盖 scratch、mkdir、ls、pwd、cd、cat、cp、mv、rm、upload、download 和 SHA-256 复核。
- 每次运行都检查 scratch 目录、`direct-https-job-*.out` 和宿主进程响应状态。

## 阅读顺序

1. [ARTIFACTS-AND-RUNS.md](ARTIFACTS-AND-RUNS.md)：最终文件指纹和三次运行摘要。
2. [RESULT.md](RESULT.md)：候选完整结论和门禁说明。
3. [IMPLEMENTATION-OVERVIEW.md](IMPLEMENTATION-OVERVIEW.md)：实现分层说明。
4. [END-TO-END-FLOW-BEGINNER.md](END-TO-END-FLOW-BEGINNER.md)：从代码到构建、部署和回连的入门讲解。
5. [WPS-DLL-TO-AGENT-CACHE-DAT-DETAILED.md](WPS-DLL-TO-AGENT-CACHE-DAT-DETAILED.md)：WPS DLL、loader、`cache.dat` 和 AgentMain 的逐函数说明。
6. [INNOVATIONS-VS-ORIGINAL-ADAPTIX.md](INNOVATIONS-VS-ORIGINAL-ADAPTIX.md)：与原版 Adaptix beacon_agent 的设计对照。
7. [KASPERSKY-PASS-ANALYSIS.md](KASPERSKY-PASS-ANALYSIS.md)：扫描阶段与结果分析。

## 证据边界

这里保存的是去敏后的源码关联文档、指标摘要和哈希清单。原始扫描 stdout、远程部署日志、Windows 进程快照和最终 `dll/dat/so` 文件继续留在本地候选目录；它们的文件指纹已经整理进 `ARTIFACTS-AND-RUNS.md` 和 `RELEASE-SHA256SUMS`。
