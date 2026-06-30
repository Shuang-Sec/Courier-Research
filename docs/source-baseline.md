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

