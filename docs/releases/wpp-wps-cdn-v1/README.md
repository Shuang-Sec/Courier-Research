# WPP/WPS direct_https CDN v1 正式归档

本目录是当前 WPP/WPS 宿主链路的正式归档入口。它对应已经完成真实 WPP/WPS 功能矩阵、CDN edge -> origin 回连验证和三层 Kaspersky 门禁的 CDN 候选。

## 版本身份

| 项目 | 值 |
|---|---|
| 版本标签 | release-wpp-wps-cdn-v1 |
| 源码基线 | 72e54efee51ee70445344a81c4580142a505b0e2 |
| origin listener | cdn_wpp_wps_v1_20260724_8448 |
| edge | 192.168.220.10:9443 |
| origin | 127.0.0.1:8448 |
| 逻辑 Host | cdn-lab.local:9443 |
| WPS/WPP 入口 | krpt.dll |
| Agent 运行时 | agent_direct_https.so |
| profile | direct_https_profile.x64.dll |
| 加密容器 | cache.dat |

## 通信链路

~~~text
WPS/WPP
  -> krpt.dll
  -> cache.dat 解密和 profile 装载
  -> direct_https Agent
  -> HTTPS 192.168.220.10:9443
  -> Python CDN-like proxy
  -> HTTPS 127.0.0.1:8448
  -> Adaptix Teamserver origin listener
~~~

代理转发时把 origin 请求的 Host 设置为 cdn-lab.local:9443，同时保留客户端来源信息并写入 X-Forwarded-For、X-Forwarded-Proto。这一步是解决初始 404 的关键配置。

## 已验收内容

- WPP/WPS 真实功能矩阵：17/17
- disks 专项：2/2
- upload/download：顺序执行并通过 SHA-256 比对
- WPP/WPS 进程：验证期间保持 Responding
- CDN edge、origin、Teamserver API：链路证据一致
- 静态扫描、系统内存扫描、新鲜 Qscan：三轮记录均为 detected=0、errors=0
- krpt.agent.dll：正式归档只使用 krpt.dll

## 目录内容

- artifacts/：已验收的核心运行产物，不包含边缘 TLS 私钥
- scripts/cdn_https_proxy.py：代理源码快照
- systemd/adaptix-cdn-proxy.service.example：开机自启动配置模板
- MANIFEST.md：候选参数、功能和产物清单
- RESULT.md：阶段验收结果
- CDN-LINK-RETROSPECTIVE.md：链路问题定位和恢复过程
- PROJECT-CONSOLIDATED-INTERVIEW-GUIDE.md：项目总览和面试问答
- SHA256SUMS：本归档核心文件哈希

完整扫描原始报告、远程部署日志、代理运行日志和证据文件继续保存在本机：

~~~text
/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809/
~~~

原始日志和靶机备份未进入 Git release，避免把临时身份、Beacon 标识、部署路径和运行时噪声扩散到版本库。

## 构建状态说明

正式归档使用的 runtime artifact 来自已完成真实验证的候选目录。仓库中的 src_beacon/Makefile 还包含单进程默认构建保护，用于降低 AdaptixClient 高内存状态下的编译峰值；该改动只影响构建并行度，不改变 Agent 协议和运行逻辑。

候选报告记录的 Go 测试当时受到本机构建环境工具链缺失影响。release 不把这项记录伪装成通过；需要复跑时，在安装 Go 的构建环境执行：

~~~bash
cd /home/chenshuang/CTF/AdaptixC2/AdaptixServer/extenders/direct_https_agent
go test ./...
~~~

## 回滚基线

直连版 release-wpp-functional-v1 仍作为回滚基线保留。CDN 版本需要同时匹配 listener watermark、callback 地址和逻辑 Host；重建同名 listener 后，应重新生成 profile 和 cache.dat。
