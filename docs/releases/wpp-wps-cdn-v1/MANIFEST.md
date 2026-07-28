# WPP/WPS direct_https 本地 CDN 候选清单

## 1. 候选身份

- 候选目录：`/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809`
- 生成日期：2026-07-24
- 源码仓库：`/home/chenshuang/CTF/AdaptixC2`
- 源码提交：`72e54efee51ee70445344a81c4580142a505b0e2`
- 基线 tag：`release-wpp-functional-v1`
- 运行时插件提交哈希：`d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779`
- 候选性质：在直连版基线旁边建立的 CDN-like 并行候选；直连 `https_8443_1` 作为回滚参考保留。

本目录保存了 profile DLL、加密后的 `cache.dat`、已经验证的单入口 `krpt.dll`、runtime plugin、边缘 TLS 证书、代理副本、三轮部署日志和功能证据。服务清理后，9443 和 8448 已释放；重新测试时使用本目录中的文件和报告恢复链路。

项目总览和面试问答入口：

- [`PROJECT-CONSOLIDATED-INTERVIEW-GUIDE.md`](/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/PROJECT-CONSOLIDATED-INTERVIEW-GUIDE.md)

## 2. 实际通信路径

计划初始地址为 `192.168.127.130:9443`。Windows 靶机地址为 `192.168.220.131`，实测它到 `192.168.127.130:9443` 的 TCP 检查结果为 `False`，到 Linux 主机的 `192.168.220.10:9443` 结果为 `True`。因此候选使用靶机实际可达的地址：

```text
WPS/WPP 192.168.220.131
    |
    | HTTPS 192.168.220.10:9443
    v
Python CDN-like 代理
    |
    | HTTPS 127.0.0.1:8448
    v
Adaptix BeaconHTTP origin listener
    |
    v
direct_https agent_direct_https.so
```

这个地址修正只改变了 profile 的 callback 地址和边缘监听位置，Agent 命令面、任务 envelope、LPT4/schema4 framing、native result bundle V4 和 opcode 保持原样。profile 中的逻辑 Host header 仍为 `cdn-lab.local:9443`。

## 3. Origin listener

- 名称：`cdn_wpp_wps_v1_20260724_8448`
- 类型：`BeaconHTTP`
- 协议：HTTPS
- 绑定：`0.0.0.0:8448`
- callback address：`192.168.220.10:9443`
- Host header：`cdn-lab.local:9443`
- HTTP method：`POST`
- URI：`/api/v1/status`、`/updates/check.php`、`/content.html`
- 心跳头：`X-Beacon-Id`
- `X-Forwarded-For`：启用
- origin server header：`Via: cdn-forward-lab`
- listener watermark：`0cbca9ca`
- 当前状态：验证完成后已通过 `/listener/stop` 停止

脱敏配置和创建/重建原因见：

- `/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/baseline/listener-create.json`
- `/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/evidence/final-api-runtime.json`
- `/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/evidence/listener-stop.json`

创建过程中发现 BeaconHTTP 的 edit 路径会丢失运行时 protocol/watermark，因此先停止再用完整 HTTPS 配置重建 listener。最终 API 快照确认 protocol 为 `https`、状态为 `Listen`、watermark 为 `0cbca9ca`。

## 4. CDN 边缘证书

- 证书：`cdn-edge.crt`
- 私钥：`cdn-edge.key`
- Subject：`CN=cdn-lab.local`
- SAN：`DNS:cdn-lab.local`、`IP:192.168.220.10`、`IP:192.168.127.130`、`IP:127.0.0.1`、`DNS:localhost`
- 有效期：2026-07-24 03:28:34 UTC 至 2028-10-26 03:28:34 UTC
- 证书 SHA-256：`be6109d51fef19205f3d70a7cb78d1e12276bdeb22f300b612fe983ae5f70531`
- 私钥 SHA-256：`518a1958b6a5703d9c0270e321a69ccb19a08d4ec9b8cd06cd72d3a9bd2ee04e`
- 检查记录：`evidence/cert-inspection.txt`

私钥文件权限为当前用户可读写。证书用于本地 CTF 网络的边缘 TLS，origin 侧仍由 Adaptix listener 处理 TLS。

## 5. 代理实现和本轮修正

候选代理副本：`cdn_https_proxy.py`，SHA-256 为：

```text
8b2482d2fa0f62e1952434ea1b80faf46c11556d5051bbf023967d9ae9944ff9
```

候选副本增加了 `--origin-host-header` 参数。代理在边缘日志中保留客户端原始 Host，并写入 `X-Forwarded-Host`；向 origin 转发时把 Host 设置为 `cdn-lab.local:9443`，同时写入 `X-Forwarded-For` 和 `X-Forwarded-Proto: https`。

实际诊断过程如下：

1. WinINet 发到边缘的 Host 是 `192.168.220.10:9443`，虽然 profile metadata 中声明了逻辑 Host header。
2. BeaconHTTP origin 对配置的 `host_header` 做严格匹配，原始转发得到 404。
3. 代理增加 origin Host 重写后，边缘日志保留原始 Host，origin 收到 `cdn-lab.local:9443`。
4. 修正后的请求全部返回合法 200 响应，三条 Agent URI 都持续出现。

最终代理汇总见 `evidence/proxy-summary.json`。原始 `proxy.log` 仍保留完整请求证据，汇总文件不包含 Beacon 标识值。

## 6. 构建和加密容器

profile 构建参数：

- x64 profile DLL
- sleep：`10s`
- jitter：`0`
- beat dialect：`2`
- lite WinINet connector
- lazy WinINet initialization
- 当前已验证的完整命令面模块：Commander、Downloader、JobsController、MemorySaver 等
- callback：`192.168.220.10:9443`
- profile Host：`cdn-lab.local:9443`

profile 元数据见 `profile_dll/build-meta.json`。其中包含：

- profile DLL：79,360 bytes
- section 数量：10
- relocation 数量：63
- import 数量：24
- TLS callback：2
- exception directory：存在
- listener watermark：`0cbca9ca`
- agent watermark：`d17ec7ed`

`cache.dat` 由 profile DLL 打包生成，外层为 `DHPLE2`，内层 profile container 为 `DHPL1`，使用 AES-256-GCM 和 PBKDF2-HMAC-SHA256，迭代次数为 100000。容器元数据见 `cache.dat.meta.json`，打包日志见 `build-logs/cache-pack.log`。

## 7. 构建产物和哈希

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `cache.dat` | 79,896 bytes | `0b8a1f17ab9102c67a454a5e8392744b18364783bb17475d97a670a491288826` |
| `krpt.dll` | 50,688 bytes | `b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac` |
| `profile_dll/direct_https_profile.x64.dll` | 79,360 bytes | `63ba4e2bb1438bd331ceaa37d780e72edd6f04041991abeaf2cf79a8a532639d` |
| `profile_dll/direct_https_profile.x64.bin` | 79,360 bytes | `c426eea160b47b18cebf2e31d20397779dcba85b80fcbedec474d4edf0a96218` |
| `profile_dll/profile.bin` | 298 bytes | `aba7ded7c178436aaa8f7af788e90452a3994bd8373ccb8edb6032a9e9a61150` |
| `agent_direct_https.so` | 5,555,176 bytes | `d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779` |
| `cdn_https_proxy.py` | 5,663 bytes | `8b2482d2fa0f62e1952434ea1b80faf46c11556d5051bbf023967d9ae9944ff9` |
| `cdn-edge.crt` | 1,249 bytes | `be6109d51fef19205f3d70a7cb78d1e12276bdeb22f300b612fe983ae5f70531` |
| `cdn-edge.key` | 1,704 bytes | `518a1958b6a5703d9c0270e321a69ccb19a08d4ec9b8cd06cd72d3a9bd2ee04e` |

可用 `sha256sum -c SHA256SUMS` 复核核心文件。

## 8. Kaspersky 三轮部署门禁

三轮均使用同一组 `cache.dat`、`krpt.dll`、profile 和代理代码，区别仅在远程部署批次名：`r1`、`r2`、`r3`。每轮结果如下：

| 批次 | cache 静态 | krpt 静态 | 系统内存 | 新鲜 Qscan | Qscan processed |
|---|---|---|---|---|---:|
| run1 | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | completed, rc 0 | 3612 |
| run2 | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | completed, rc 0 | 3612 |
| run3 | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 | completed, rc 0 | 3612 |

表格中的三元组顺序为 `Processed / detected / errors`。所有新鲜 Qscan 的 detected 和 errors 均为 0。完整报告路径：

- 首轮：候选根目录下的 `static-scan-*.report.txt`、`kaspersky-memory.report.txt`、`kaspersky-qscan.report.txt`
- 第二轮：`evidence/runs/run2/`
- 第三轮：`evidence/runs/run3/`
- profile DLL 独立扫描：`evidence/static-scan-profile.log`

## 9. 功能验证

### 9.1 自动化矩阵

首轮 WPP 和 WPS 都完成 `17/17`。run2 两边的任务状态也都是 `17/17`。run3 重新启动后，第一次选 Agent 的 5 秒窗口落在重连时序内，随后重试取得新 Agent 并完成 `17/17`；之后又按顺序单独执行 WPP 和 WPS，得到没有下载文件竞争的 `17/17` 结果。

顺序复验使用的 Agent：

- WPP：`b3b4822f`
- WPS：`10d75d24`

### 9.2 注册命令覆盖

当前注册的 14 项能力已覆盖：

`hello`、`cmd`、`powershell`、`pwd`、`cd`、`ls`、`cat`、`mkdir`、`rm`、`cp`、`mv`、`disks`、`upload`、`download`。

17 项自动化矩阵覆盖了命令执行、路径切换、文件创建、读取、复制、移动、删除、上传和下载；`disks` 作为专项任务单独执行。run3 的 WPP/WPS `disks` 均返回：

```text
C: fixed (3)
D: cdrom (5)
```

### 9.3 传输哈希

首轮顺序矩阵的 WPP/WPS 下载内容均为 49 bytes，实际 SHA-256 与上传内容一致；run3 顺序复验的 WPP/WPS 下载内容同样全部一致并完成服务器文件清理。

证据：

- `evidence/download-hash-check.json`
- `evidence/download-hash-check-run3-sequential.json`
- `evidence/runs/run3-sequential/`

run2/run3 初始并行矩阵产生了同名下载回收文件，后完成的任务覆盖先完成任务的服务器文件。该现象已经在 `evidence/download-hash-check-r2-r3.json` 中原样记录，并通过 run3 顺序复验消除测试编排干扰。

## 10. 运行状态和清理

在线验证结束前的快照：

- Windows 到 `192.168.220.10:9443`：`True`
- WPP/WPS：`Responding=True`
- listener：`https`、`Listen`
- latest WPP/WPS Agent 均出现在 CDN listener 下
- `C:\Users\Public\direct-https-job-*.out`：0
- WPP/WPS scratch：0
- 临时 profile：已删除
- `krpt.agent.dll`：不存在，部署包只使用 `krpt.dll`

清理后：

- Python 9443 代理进程已停止
- 8448 origin listener 已停止
- Linux `ss` 检查确认 9443/8448 均无监听
- WPP/WPS 测试进程已停止
- 下载回收文件已完成哈希核对后删除

证据：`evidence/final-runtime-cleanup.txt`、`evidence/windows-process-cleanup.txt`、`evidence/service-cleanup.txt`、`evidence/listener-stop.json`。

## 11. 构建门禁和遗留项

- C++ x86 对象构建：通过，日志为 `build-logs/cpp-x86-build.log`
- x64 profile DLL 构建：通过，日志为 `build-logs/profile-build.log`
- `git diff --check`：通过
- `SHA256SUMS`：已生成
- Go 单元测试：当前执行环境 PATH 没有 `go`，日志 `build-logs/go-test.log` 记录了 `go: command not found`；这项需要在安装 Go 的构建环境重新执行

因此本目录适合作为已经通过真实 WPP/WPS CDN 链路和三轮 AV 门禁的候选归档。正式 release tag 仍应在 Go 测试补跑、并行下载测试脚本改为顺序执行后再创建；直连版仍然是回滚基线。

## 12. 推荐复跑顺序

1. 通过 Adaptix API 使用脱敏配置重新创建或启动 `cdn_wpp_wps_v1_20260724_8448`，保持 callback、Host、URI、watermark 和 HTTPS 配置与 `listener-create.json` 一致。
2. 使用下列命令启动边缘代理：

```bash
python3 /home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/cdn_https_proxy.py \
  --listen-host 0.0.0.0 --listen-port 9443 \
  --origin-host 127.0.0.1 --origin-port 8448 \
  --origin-host-header cdn-lab.local:9443 \
  --cert /home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/cdn-edge.crt \
  --key /home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/cdn-edge.key \
  --log /home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/proxy.log
```

3. 使用 `cache.dat` 和 `krpt.dll` 部署到 WPS office6 目录。
4. 先检查 Windows 到 `192.168.220.10:9443`，再启动 WPP/WPS。
5. 观察 `proxy-summary.json` 对应的 200 流量，按顺序执行 WPP 矩阵，再执行 WPS 矩阵，最后执行 `disks`。

## 13. GitHub 研究

研究矩阵见 `evidence/github-research.md`，覆盖 AdaptixC2、MythicAgents/Xenon、RedEdr 和 CAPEv2，并记录了读取提交、模块边界、profile/能力组织、运行时观测和证据留存方面的借鉴点。

## 14. CDN 链路复盘

完整过程、故障定位、runtime restore、systemd 自启动和最终验证见 `CDN-LINK-RETROSPECTIVE.md`。
