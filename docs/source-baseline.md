# 导出基线说明

这个私有 GitHub 快照来自本地工作树的一个稳定检查点，核心对应的是：

- 原始本地仓库：`AdaptixC2`
- 本地分支：`feature/direct-https-minimal-agent`
- 本地基线 tag：`local-baseline-2026-06-30-profile-loader-dhple2`
- 基线 commit：`4676edf`

## 导出策略

这次没有直接把整棵本地仓库原样推送，而是单独导出了一个去敏快照：

- 保留：源码、loader/packer、关键脚本、去敏总结文档
- 去掉：原始 reports、生成的 exe/dll/bin、Windows 落地文件、账号路径、内网 IP、默认 key/密码

## 原始本地近期演进（摘要）

- `a28ff07` feat: probe PE header artifacts in memory loader
- `17871fb` feat: add DHPL1 profile-only loader
- `3a3a839` feat: encrypt DHPL container with AES-GCM
- `a0d52ed` feat: add DHPLE2 PBKDF2 profile loader
- `eeaa951` feat: add profile loader release variants
- `4676edf` feat: checkpoint local baseline for profile-only loader dhple2

## 2026-07-21 WPP/WPS 功能候选快照

最近一次本地功能候选对应：

- 原始本地仓库：`AdaptixC2`
- 本地分支：`feature/direct-https-minimal-agent`
- 源码提交：`72e54efee51ee70445344a81c4580142a505b0e2`
- 本地标签：`release-wpp-functional-v1`
- 候选范围：F0 文件输出后备、F1 命令执行、F2 文件 CRUD、F3 上传下载
- 证据目录：`docs/evidence/2026-07-21-wpp-wps-f0-ps-encoding/`

这次更新仍然采用筛选式导出：同步源码、构建脚本、协议测试和去敏报告；最终 Windows/Linux 运行产物只在本地候选目录保存，并用 SHA-256 清单关联。
