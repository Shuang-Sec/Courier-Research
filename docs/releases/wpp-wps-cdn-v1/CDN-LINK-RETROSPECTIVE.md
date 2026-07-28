# WPP/WPS direct_https CDN 链路完整复盘

更新时间：2026-07-24 15:10（Asia/Shanghai）

本文记录当前 WPP/WPS direct_https Agent 接入本地 CDN-like HTTPS 代理的完整过程。内容按照“目标、架构、构建、部署、排错、恢复、自启动、最终验证”的顺序展开，重点说明每一层程序的职责，以及曾经出现的离线和 404 问题分别属于哪一层。

本文只记录当前 CTF 靶场中的固定环境和证据，不把不同阶段的临时状态混为一个版本。尤其要区分：

- 正式 CDN 候选使用的 listener watermark 和 `cache.dat`。
- 清理后重新创建 listener 产生的 runtime restore watermark 和 `cache.dat`。
- 当前 systemd 管理的代理进程和当前在线 Agent。

## 一、最终结论

当前实际运行链路为：

```text
WPP/WPS 进程中的 direct_https Agent
    |
    | HTTPS 192.168.220.10:9443
    v
Python CDN-like 边缘代理
    |
    | HTTPS 127.0.0.1:8448
    v
AdaptixServer 的 cdn_wpp_wps_v1_20260724_8448 origin listener
    |
    v
direct_https Agent 任务、结果和回连状态
```

当前关键运行参数：

| 项目 | 当前值 |
|---|---|
| Windows 靶机 | `192.168.220.131` |
| Linux 边缘地址 | `192.168.220.10:9443` |
| Python 代理 origin | `127.0.0.1:8448` |
| origin listener | `cdn_wpp_wps_v1_20260724_8448` |
| origin Host header | `cdn-lab.local:9443` |
| Agent callback | `192.168.220.10:9443` |
| Agent sleep | `10s` |
| jitter | `0` |
| heartbeat dialect | `2` |
| Python 代理服务 | `adaptix-cdn-proxy.service` |

最终状态检查结果：

```text
adaptix-cdn-proxy.service: enabled / active
adaptixserver.service: enabled / active
Linger=yes
9443: python3 PID 118601
8448: adaptixserver PID 2534
```

最后一次实时检查发现 4 个新鲜 CDN Agent：1 个 WPP、3 个 WPS。Windows 侧对应的 `wpp.exe` 和 `wps.exe` 进程均为 `Responding=True`，代理日志持续收到真实请求且 origin 返回 `200`。

## 二、先理解几个名词

### 2.1 Agent 是什么

Agent 是运行在 WPP/WPS 进程内部的 direct_https 代码。它负责：

1. 按 profile 中的地址发起 HTTPS 请求。
2. 首次请求时向 Teamserver 报到，也就是 check-in。
3. 周期性发送 heartbeat，表示进程仍然在线。
4. 读取服务端下发的任务。
5. 执行当前注册的命令。
6. 把命令结果重新编码并回传。

Agent 本身并不知道“前面有一个 CDN-like 代理”。对 Agent 来说，它只是连接 profile 中的 callback 地址 `192.168.220.10:9443`。

### 2.2 Edge、代理和 origin 的关系

可以把三层理解成三个不同的门：

- **Edge**：Windows 看到的第一扇门，当前是 `192.168.220.10:9443`。
- **Python 代理**：接收 edge 请求，再把请求转发到本机 origin。
- **Origin listener**：AdaptixServer 真正识别 Agent、入库 check-in、派发任务和保存结果的 listener，当前是 `127.0.0.1:8448`。

所以 `9443` 和 `8448` 的职责不同：

```text
9443 = Windows 靶机可达的边缘入口
8448 = Teamserver 内部接收 Agent 协议的 origin 入口
```

### 2.3 Profile 和 cache.dat 的关系

profile 是 Agent 的通信配置，里面包含 callback、Host、URI、sleep、jitter、heartbeat 相关参数等。profile DLL 会被打包进加密容器，最终形成 `cache.dat`。

本项目的 `cache.dat` 外层格式是 `DHPLE2`，内部 profile container 是 `DHPL1`。它使用 AES-256-GCM 和 PBKDF2-HMAC-SHA256 保护内容。

“文件是加密的”和“profile 中存在 listener watermark”可以同时成立：

- 外部直接查看时，`cache.dat` 不是明文配置文件。
- Loader 解密后，内层 profile 仍然包含 callback、Host 和 watermark 等运行参数。
- Teamserver 通过 watermark 将回连归属到正确 listener。

因此 listener 被重建后，旧 `cache.dat` 和新 listener 的 watermark 可能不匹配，这就是后面恢复阶段需要重新生成 runtime cache 的原因。

## 三、直连版为什么要增加 CDN-like 链路

直连版路径是：

```text
WPP/WPS Agent -> 192.168.220.10:8443 -> AdaptixServer 直连 listener
```

CDN 候选路径是：

```text
WPP/WPS Agent -> 192.168.220.10:9443 -> Python 代理 -> 127.0.0.1:8448 -> Adaptix origin
```

这次改动的边界很窄：

- Agent 的命令实现保持原来的已验证版本。
- Go/C++ opcode 和任务 envelope 保持原样。
- LPT4/schema4 section framing 保持原样。
- native result bundle V4 保持原样。
- `krpt.dll` 继续使用已经验证过的入口 DLL。
- 只改变 profile 的 callback 地址和 Host header，并在 Linux 侧增加一个转发层。

这样做的好处是排查时可以把“Agent 代码问题”和“网络路径问题”分开。命令仍由原来的 Agent 处理，新增变量主要集中在 edge、Host、origin 和 listener watermark。

## 四、时间线总览

| 阶段 | 主要动作 | 关键结论 |
|---|---|---|
| F0 基线确认 | 记录直连版本、源码、artifact 和运行环境 | 直连版保留为回滚基线 |
| CDN 预检 | 检查靶机到 edge 的可达性 | 计划地址不可达，改用 `192.168.220.10:9443` |
| origin 创建 | 创建隔离的 HTTPS listener `8448` | 需要完整保留 protocol 和 watermark |
| 边缘证书 | 生成 `cdn-lab.local` 实验室证书 | TLS edge 握手可用 |
| 第一版代理 | 启动 Python HTTPS 转发 | 原始 Host 转发导致 origin 404 |
| Host 修正 | 加入 `--origin-host-header` | 真实 Agent 请求恢复为 200 |
| profile 构建 | 生成 callback 为 `9443` 的 profile 和 `cache.dat` | 逻辑代码保持基线版本 |
| 三轮门禁 | 静态、内存、Qscan 和功能矩阵 | 三轮 AV 门禁通过，功能矩阵通过 |
| 初次清理 | 停止代理和 origin | 归档状态正常，但之后 Agent 不再上线 |
| runtime restore | 重建 listener，生成匹配 watermark 的 cache | WPP/WPS 重新上线 |
| 自启动 | 使用用户级 systemd 接管代理 | 代理具备开机启动和异常重启能力 |

## 五、第一阶段：确认靶机真正可达的边缘地址

计划里最初写的是：

```text
192.168.127.130:9443
```

实际从 Windows 靶机 `192.168.220.131` 检查时：

```text
192.168.127.130:9443 -> TcpTestSucceeded=False
192.168.220.10:9443  -> TcpTestSucceeded=True
```

因此最终使用：

```text
callback = 192.168.220.10:9443
edge listen = 0.0.0.0:9443
```

这一步很重要，因为 profile 中的地址必须同时满足两个条件：

1. Windows 靶机能够访问。
2. Linux 上确实有程序监听这个端口。

如果只修改 profile 而没有检查靶机路由，Agent 会一直按照自己的配置发起请求，但请求根本到不了边缘代理。

## 六、第二阶段：创建隔离的 origin listener

创建的 listener 参数如下：

```text
名称：cdn_wpp_wps_v1_20260724_8448
协议：HTTPS
绑定：0.0.0.0:8448
callback：192.168.220.10:9443
Host header：cdn-lab.local:9443
```

第一轮配置过程中遇到一个重要现象：某些 edit 路径会让 HTTPS protocol 或运行时 watermark 丢失。后续采用“停止后使用完整配置重新创建”的方式，最终 API 快照确认：

```json
{
  "status": "Listen",
  "protocol": "https",
  "bind": "0.0.0.0:8448",
  "callback": "192.168.220.10:9443",
  "watermark": "0cbca9ca",
  "host_header": "cdn-lab.local:9443"
}
```

正式候选的 listener watermark 是 `0cbca9ca`。这个值会被写入正式候选的 profile 和 `cache.dat`。

listener watermark 可以理解为“这个 Agent 应该归属哪个 listener 的内部标识”。它不是公开端口，也不是 Host header；它是 Agent profile 与 Teamserver listener 之间的匹配信息。

## 七、第三阶段：生成边缘 TLS 证书

边缘代理需要先完成 TLS 握手，再把 HTTP 请求转发到 origin。因此单独生成了边缘证书：

```text
Subject: CN=cdn-lab.local
SAN:
  DNS:cdn-lab.local
  IP:192.168.220.10
  IP:192.168.127.130
  IP:127.0.0.1
  DNS:localhost
```

证书留存在候选目录：

```text
/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/cdn-edge.crt
/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/cdn-edge.key
```

证书的作用范围是 edge：

```text
Windows Agent -> edge 9443：使用 cdn-edge.crt/cdn-edge.key
Python 代理 -> origin 8448：使用当前代理代码的本地 origin TLS 策略
```

证书自签名提示属于实验室证书属性。实际 WPP/WPS Agent 请求已经完成 TLS 和 origin 转发，判断链路时以真实 Agent 请求日志为准。

## 八、第四阶段：Python 代理如何转发

代理源码副本是：

```text
/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/cdn_https_proxy.py
```

代理收到 edge 请求后执行的核心流程：

```text
读取请求方法、URI、Content-Length 和 body
    -> 过滤逐跳 HTTP 头
    -> 记录客户端原始 Host
    -> 写入 X-Forwarded-Host
    -> 把发往 origin 的 Host 改成 cdn-lab.local:9443
    -> 写入 X-Forwarded-For: 192.168.220.131
    -> 写入 X-Forwarded-Proto: https
    -> 通过 HTTPS 访问 127.0.0.1:8448
    -> 读取 origin 响应
    -> 原样返回主要响应头和 body
    -> 追加一条 JSON 请求日志
```

请求头变化可以用下表理解：

| 位置 | Host | 其他关键字段 |
|---|---|---|
| Windows 发给 edge | `192.168.220.10:9443` | Agent 自带 `X-Beacon-Id` |
| 代理日志 | 保留原始 Host | 记录客户端、URI、body hash、响应 hash |
| 代理发给 origin | `cdn-lab.local:9443` | `X-Forwarded-Host`、`X-Forwarded-For`、`X-Forwarded-Proto` |

## 九、第一次 404：真正原因是 Host mismatch

初始代理版本把 Windows 看到的原始 Host 直接转发给 origin。Windows Agent 实际发送的 Host 是：

```text
192.168.220.10:9443
```

而 origin listener 配置的逻辑 Host 是：

```text
cdn-lab.local:9443
```

BeaconHTTP origin 对 Host 做严格匹配，于是出现：

```text
edge 收到请求
代理也成功连到 8448
origin 返回 HTTP 404
Agent 没有得到合法的 check-in 响应
```

这个 404 说明 TCP、TLS 和代理转发至少已经走到 origin，问题集中在 HTTP 路由匹配层，不是 WPP/WPS 进程崩溃。

修复方式是增加：

```text
--origin-host-header cdn-lab.local:9443
```

同时保留边缘原始 Host 到日志，并加入 `X-Forwarded-Host`，这样既满足 origin 的逻辑 Host 匹配，又保留了现场审计信息。

修复后：

- 早期诊断记录中有 367 条 404。
- Host 修正后的代理汇总有 1427 条 200。
- 修正后的三条 Agent URI 都持续收到真实请求。

## 十、第五阶段：重新生成 profile 和加密 cache

正式 CDN 候选沿用已验证的 Agent 代码，只替换通信配置。构建参数为：

```text
x64
sleep=10s
jitter=0
beat_dialect=2
lite WinINet connector=true
lazy WinINet initialization=true
callback=192.168.220.10:9443
host_header=cdn-lab.local:9443
```

profile 元数据中包含：

```text
listener watermark = 0cbca9ca
agent watermark    = d17ec7ed
URI                = /api/v1/status
                     /updates/check.php
                     /content.html
heartbeat header   = X-Beacon-Id
```

之后执行：

```text
direct_https_profile.x64.dll
    -> profile.bin / 内层 profile section
    -> DHPLE2 外层容器
    -> AES-256-GCM + PBKDF2-HMAC-SHA256
    -> cache.dat
```

正式候选的核心文件：

| 文件 | SHA-256 |
|---|---|
| 正式候选 `cache.dat` | `0b8a1f17ab9102c67a454a5e8392744b18364783bb17475d97a670a491288826` |
| `krpt.dll` | `b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac` |
| `agent_direct_https.so` | `d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779` |

`krpt.dll` 是 WPS/WPP 侧的入口 loader。它读取同目录的 `cache.dat`，解密并加载 profile，随后 Agent 按 profile 中的 edge 地址发起通信。当前候选交付只使用 `krpt.dll`，不额外依赖 `krpt.agent.dll`。

## 十一、第六阶段：三轮 AV 和功能验证

每轮的门禁顺序基本固定：

```text
停止旧 WPP/WPS
    -> 备份远程文件
    -> 上传 cache.dat / krpt.dll
    -> 校验远程 SHA-256
    -> Kaspersky 静态扫描
    -> Scan_System_Memory
    -> 等待旧 Qscan 结束
    -> 启动新鲜 Scan_Qscan
    -> 启动 WPP_ActiveV2_Live_Test_Limited
    -> 等待回连
    -> 执行功能矩阵
    -> 保存任务、回连和清理证据
```

三轮门禁结果：

| 批次 | cache 静态 | krpt 静态 | 系统内存 | 新鲜 Qscan |
|---|---|---|---|---|
| run1 | `1/0/0` | `1/0/0` | `1/0/0` | 3612 processed，0 detected，0 errors，rc 0 |
| run2 | `1/0/0` | `1/0/0` | `1/0/0` | 3612 processed，0 detected，0 errors，rc 0 |
| run3 | `1/0/0` | `1/0/0` | `1/0/0` | 3612 processed，0 detected，0 errors，rc 0 |

三元组顺序是：

```text
Processed / Detected / Errors
```

当前注册的 14 项能力为：

```text
hello、cmd、powershell、pwd、cd、ls、cat、mkdir、rm、cp、mv、disks、upload、download
```

自动化矩阵按 17 个任务记录，首轮和后续顺序复验均完成 `17/17`。`disks` 专项结果为 `2/2`，实际驱动器为：

```text
C: fixed (3)
D: cdrom (5)
```

## 十二、并行下载证据问题和顺序复验

run2/run3 初始测试同时启动 WPP 和 WPS 两个矩阵。两个任务在同一秒产生相同服务器回收文件名，后写入的任务覆盖了先写入的文件。

这造成了一个容易误判的现象：

- 两个 Agent 的任务数据库状态仍为 `completed`。
- 代理和 origin 仍在正常工作。
- 某一份服务器回收文件的内容属于另一侧 marker。

根因是测试编排中的同名文件竞争，不是 upload/download 协议错误。

随后在 run3 新部署进程上改为严格顺序：

```text
先完整执行 WPP
    -> 保存 WPP 下载文件和 SHA-256
    -> 清理 WPP scratch
再完整执行 WPS
    -> 保存 WPS 下载文件和 SHA-256
    -> 清理 WPS scratch
```

顺序复验后，WPP/WPS 的上传内容和下载回收内容均一致，文件大小均为 49 bytes，服务器临时文件也完成删除。以后复跑固定采用顺序矩阵。

## 十三、为什么后来看不到 CDN Agent

### 13.1 第一层原因：清理动作关闭了链路

第一次 CDN 候选验证结束后执行了归档清理：

- 停止 Python `9443` 代理。
- 停止 `8448` origin listener。
- 停止 WPP/WPS 测试进程。
- 释放 `9443` 和 `8448` 端口。

这个状态适合测试结束后的归档，不适合随后直接打开 WPS 等待 Agent 上线。Windows 进程即使仍然存在，profile 配置的 edge 地址也没有服务接收请求。

当时现场表现为：

```text
Teamserver API 4321：正常
直连 listener 8443：正常
CDN edge 9443：没有监听
CDN origin 8448：没有监听
Windows -> 192.168.220.10:9443：False
```

所以 UI 看不到 Agent 的第一直接原因是：CDN 链路的两个服务已经被清理流程主动关闭。

### 13.2 第二层原因：listener 重建产生了新 watermark

恢复时重新创建同名 listener，Teamserver 为新实例生成了：

```text
新 listener watermark：89fe0e98
```

正式候选原来的 `cache.dat` 里仍然是：

```text
旧正式 listener watermark：0cbca9ca
```

即使 edge 和 origin 的 HTTP 表面响应正常，Agent profile 与 listener 的身份标识也没有完全对应。这个阶段容易出现“代理日志有请求，但 UI 没有对应新鲜 Agent”的中间状态。

### 13.3 恢复方式

为新 listener 生成了独立 runtime restore profile 和 cache：

```text
runtime restore listener watermark：89fe0e98
agent watermark：d17ec7ed
callback：192.168.220.10:9443
Host：cdn-lab.local:9443
```

runtime restore cache：

```text
路径：evidence/runtime-restore-20260724/cache.dat
SHA-256：9146d7117e18c6d46d2a9cd49fae2f0fdab2765fbd21f5bf8d378f2bc786f58e
```

这份 runtime cache 与正式候选的 `cache.dat` 分开保存，正式候选文件没有被覆盖。恢复时只替换了远端运行副本的 `cache.dat`，`krpt.dll` 继续使用原来已经验证过的版本。

## 十四、runtime restore 重新部署和验证

恢复流程如下：

```text
重新创建完整 HTTPS origin listener
    -> 读取新 watermark 89fe0e98
    -> 按新 listener 生成 runtime profile
    -> 打包 runtime restore cache.dat
    -> 远程替换 cache.dat
    -> 保留原 krpt.dll
    -> 重新执行 Kaspersky 三层门禁
    -> 启动代理和 WPP/WPS
    -> 检查真实 callback
```

runtime restore 门禁结果：

| 对象 | Processed | Detected | Errors | 结果 |
|---|---:|---:|---:|---|
| runtime `cache.dat` 静态扫描 | 1 | 0 | 0 | PASS |
| `krpt.dll` 静态扫描 | 1 | 0 | 0 | PASS |
| `Scan_System_Memory` | 1 | 0 | 0 | PASS |
| 新鲜 `Scan_Qscan` | 3656 | 0 | 0 | PASS |

最小功能检查：

```text
WPP hello -> completed，ok
WPP pwd   -> completed，office6
WPS hello -> completed，ok
WPS pwd   -> completed，office6
```

这说明恢复后的问题定位是正确的：先恢复可达 edge，再恢复 origin，再保证 watermark 与 cache 对应，Agent 就重新出现在正确 listener 下。

## 十五、第七阶段：配置 CDN 代理开机自启动

手工运行 Python 进程时，终端关闭、进程退出或机器重启都可能让 `9443` 消失。为此增加用户级服务：

```text
/home/chenshuang/.config/systemd/user/adaptix-cdn-proxy.service
```

服务的关键配置：

```ini
Wants=adaptixserver.service
After=adaptixserver.service
Restart=always
RestartSec=5s
KillSignal=SIGTERM
```

启动后还会同时等待：

```text
9443 = Python edge proxy
8448 = Adaptix origin listener
```

用户级 systemd 的 `Linger` 状态已经是：

```text
Linger=yes
```

因此当前链路具备以下恢复能力：

1. Linux 用户服务管理器启动时自动拉起 AdaptixServer 和 CDN 代理。
2. 代理进程退出后 5 秒自动重启。
3. 代理启动完成前检查 edge 和 origin 两个端口。
4. 代理重新监听后，WPP/WPS Agent 可以继续发送 heartbeat。

本次没有执行整机重启，以保持当前靶机 WPP/WPS 测试状态连续；已经完成多次 systemd restart、端口等待、TLS、日志、实时 Agent 和功能回归验证。

## 十六、最终验证快照

### 16.1 服务和端口

```text
adaptix-cdn-proxy.service: enabled
adaptix-cdn-proxy.service: active
adaptixserver.service: enabled
adaptixserver.service: active
Linger=yes

0.0.0.0:9443 -> python3 PID 118601
*:8448       -> adaptixserver PID 2534
```

### 16.2 Agent 在线

最后一次 API 检查的 fresh Agent：

```text
WPP a4e9c5e6 PID 12416 age 2s
WPS 286e91ae PID 9312 age 4s
WPS 9d026b71 PID 13072 age 4s
WPS c0be6e92 PID 5340 age 2s
```

Windows 进程状态：

```text
wpp.exe PID 12416 Responding=True
wps.exe PID 5340  Responding=True
wps.exe PID 9312  Responding=True
wps.exe PID 13072 Responding=True
```

### 16.3 代理日志

最终日志持续出现：

```text
client=192.168.220.131
host=192.168.220.10:9443
origin_host=cdn-lab.local:9443
status=200
error=empty
```

典型 URI 包括：

```text
/api/v1/status
/updates/check.php
/content.html
```

## 十七、故障定位顺序

以后看到 UI 中没有 CDN Agent，按以下顺序检查，不要先重新编译 Agent：

### 第一步：检查服务

```bash
systemctl --user is-active adaptixserver.service
systemctl --user is-active adaptix-cdn-proxy.service
```

### 第二步：检查端口

```bash
ss -lntp | rg ':(8448|9443)\b'
```

### 第三步：检查代理日志

```bash
tail -n 30 /home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/evidence/runtime-restore-20260724/proxy.log
```

判断方法：

| 现象 | 优先检查层 |
|---|---|
| `9443` 没监听 | systemd、证书、端口占用 |
| `9443` 有监听，日志没有 Windows 请求 | Windows 路由、profile callback、靶机网络 |
| 日志有请求但大量 502 | `8448`、AdaptixServer、origin listener |
| 日志 404 | origin Host header、URI、listener HTTP 配置 |
| HTTP 200 但 UI 没新 Agent | cache 与 listener watermark、Teamserver listener 状态 |
| Agent 有时出现有时消失 | 服务重启、端口竞争、WPP/WPS 进程状态 |
| 下载文件内容互相覆盖 | 测试脚本并行写同名回收文件 |

## 十八、当前文件和证据索引

候选根目录：

```text
/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809
```

重点文件：

- [候选结果](./RESULT.md)
- [候选清单和哈希](./MANIFEST.md)
- [CDN 代理开机自启动记录](./evidence/runtime-restore-20260724/AUTOSTART.md)
- [Agent 不上线根因和恢复记录](./evidence/runtime-restore-20260724/ROOT-CAUSE-AND-RESTORE.md)
- [运行时 listener 快照](./evidence/runtime-restore-listener.json)
- [runtime profile 构建元数据](./evidence/runtime-restore-20260724/profile_dll/build-meta.json)
- [runtime cache 打包元数据](./evidence/runtime-restore-20260724/cache.dat.meta.json)
- [runtime 部署和扫描日志](./evidence/runtime-restore-20260724/deploy-scan.log)
- [runtime Qscan 报告](./evidence/runtime-restore-20260724/kaspersky-qscan.report.txt)
- [runtime 最小功能结果](./evidence/runtime-restore-20260724/minimal-functional-check.json)
- [当前代理请求日志](./evidence/runtime-restore-20260724/proxy.log)
- [systemd 服务定义](./evidence/runtime-restore-20260724/adaptix-cdn-proxy.service)

## 十九、复盘后的核心经验

1. 先验证 Windows 到 edge 的真实 TCP 可达性，再决定 profile 地址。
2. CDN-like 代理不仅是端口转发，Host header 也属于协议配置的一部分。
3. listener 名称相同不代表 listener 身份相同，重建后要重新比对 watermark。
4. 加密的 `cache.dat` 仍然包含运行时 profile，listener 与 cache 必须成对管理。
5. 代理、origin、Agent、Teamserver 是四个不同观察点，排错时要逐层确认。
6. 并行测试可能污染证据，尤其是使用固定回收文件名的 upload/download 流程。
7. 测试清理和长期运行是两种不同状态，完成清理后要有显式的恢复或自启动步骤。
8. 自启动服务要同时关注进程、端口、依赖服务和日志，单看 `active` 还要确认 socket 已经监听。
