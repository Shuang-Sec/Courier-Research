# WPP/WPS direct_https 本地 CDN 候选结果

## 结论

本次生成了一个独立的 WPP/WPS direct_https CDN-like 候选，真实路径为：

```text
WPP/WPS -> HTTPS 192.168.220.10:9443 -> Python 代理 -> HTTPS 127.0.0.1:8448 -> Adaptix origin -> direct_https Agent
```

核心链路、三轮 Kaspersky 门禁、首轮功能矩阵、第三轮顺序化功能复验均完成。候选归档状态为：

```text
CDN_CANDIDATE=PASS
KASPERSKY_3_DEPLOYMENTS=PASS
WPP_FUNCTION_MATRIX=PASS
WPS_FUNCTION_MATRIX=PASS
DISKS_MATRIX=PASS
TRANSFER_HASH_SEQUENTIAL_RECHECK=PASS
GO_TEST=ENVIRONMENT_GAP
SERVICE_CLEANUP=PASS
```

当前目录作为候选包留存，直连版继续作为回滚基线。Go 测试需要在具备 Go 工具链的构建环境补跑后再创建正式 release tag。

项目总览和面试问答：

- [`PROJECT-CONSOLIDATED-INTERVIEW-GUIDE.md`](/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/PROJECT-CONSOLIDATED-INTERVIEW-GUIDE.md)

## 关键过程

### 1. 基线和实际网络地址

源码固定在提交 `72e54efee51ee70445344a81c4580142a505b0e2`，基线 tag 为 `release-wpp-functional-v1`。计划地址 `192.168.127.130:9443` 从 Windows 靶机侧不可达，实测可达边缘为 `192.168.220.10:9443`。候选 profile、证书 SAN 和代理日志均按实际可达地址完成。

### 2. origin listener

创建了隔离 listener `cdn_wpp_wps_v1_20260724_8448`，绑定 `0.0.0.0:8448`，callback 为 `192.168.220.10:9443`，Host header 为 `cdn-lab.local:9443`。一次 edit 操作会丢失 HTTPS protocol/watermark，随后用完整配置重建；最终 listener API 快照确认 HTTPS、Listen 和 watermark `0cbca9ca`。

### 3. 代理 Host 修正

初始代理保持原始 Host 转发时，Windows WinINet 实际发送的 Host 是边缘 IP，origin 严格匹配逻辑 Host 后返回 404。候选代理增加 `--origin-host-header`：

- 日志保留边缘原始 Host；
- 加入 `X-Forwarded-Host`；
- 向 origin 发送 `Host: cdn-lab.local:9443`；
- 加入 `X-Forwarded-For: 192.168.220.131`；
- 保持 `X-Forwarded-Proto: https`。

修正后来自 Windows 的请求全部命中 origin，响应为 200。代理汇总共有 1427 条修正后的 200 请求，覆盖三条 URI；早期 367 条 404 只属于修正前的诊断记录。

### 4. profile 和容器

使用 x64、sleep 10s、jitter 0、beat dialect 2、lite WinINet、lazy WinINet 初始化构建 profile DLL，再打包为 DHPLE2 外层的 `cache.dat`。功能代码和 `agent_direct_https.so` 保持已验证版本，只改变 callback/Host profile 参数。`krpt.dll` 直接复用已通过 WPS 验证的入口，候选包只保留这一份入口 DLL。

### 5. Kaspersky 门禁

三次独立部署都重新上传同一组产物并执行静态扫描、系统内存扫描和新鲜 Qscan：

| 部署 | cache 静态 | krpt 静态 | 内存 | Qscan |
|---|---|---|---|---|
| run1 | 1/0/0 | 1/0/0 | 1/0/0 | 3612 processed, 0 detected, 0 errors, rc 0 |
| run2 | 1/0/0 | 1/0/0 | 1/0/0 | 3612 processed, 0 detected, 0 errors, rc 0 |
| run3 | 1/0/0 | 1/0/0 | 1/0/0 | 3612 processed, 0 detected, 0 errors, rc 0 |

三元组顺序为 `Processed / detected / errors`。profile DLL 另行扫描也为 detected 0、errors 0。

### 6. WPP/WPS 功能

首轮 WPP/WPS 均完成 17/17。第三轮新进程完成后，WPP 顺序矩阵和 WPS 顺序矩阵均完成 17/17，`disks` 专项为 2/2；两侧实际驱动器均为 `C: fixed (3)`、`D: cdrom (5)`。

顺序复验还对 upload/download 做了 SHA-256 对比：WPP 和 WPS 文件大小均为 49 bytes，上传内容和回收内容完全一致，服务器下载文件随后删除。

## 关于 run2/run3 并行证据

run2 和 run3 初始矩阵为了节省时间同时启动 WPP、WPS 两个脚本。两个 download 任务在同一秒产生相同服务器回收文件名，后写入的一方覆盖前一方，因此并行证据中出现一个文件缺失或内容属于另一 marker 的情况。两个 Agent 的任务本身仍然是 completed 17/17；该现象是测试脚本并发写同名回收文件造成的证据污染。

随后在同一 run3 新部署进程上改为严格顺序执行，得到独立 WPP/WPS 下载文件和两份匹配哈希。以后复跑固定采用顺序矩阵。

## 清理结果

- `C:\Users\Public\direct-https-job-*.out`：0
- WPP scratch：0
- WPS scratch：0
- 临时 profile：已删除
- `krpt.agent.dll`：不存在
- 下载回收文件：哈希验证后删除
- Python 9443 代理：已停止
- 8448 origin listener：已停止
- Linux 9443/8448：无监听
- WPP/WPS 测试进程：已停止

清理证据：

- `evidence/final-runtime-cleanup.txt`
- `evidence/windows-process-cleanup.txt`
- `evidence/service-cleanup.txt`
- `evidence/listener-stop.json`

## 证据索引

- 构建参数和 profile 元数据：`profile_dll/build-meta.json`
- cache 容器元数据：`cache.dat.meta.json`
- 构建日志：`build-logs/`
- 三轮部署与扫描：`deploy-scan.log`、`evidence/runs/run2/`、`evidence/runs/run3/`
- 顺序功能复验：`evidence/runs/run3-sequential/`
- 代理统计：`evidence/proxy-summary.json`
- API 运行快照：`evidence/final-api-runtime.json`
- 下载哈希：`evidence/download-hash-check.json`、`evidence/download-hash-check-run3-sequential.json`
- 文件哈希清单：`SHA256SUMS`
- GitHub 研究矩阵：`evidence/github-research.md`
- CDN 链路完整复盘：`CDN-LINK-RETROSPECTIVE.md`
