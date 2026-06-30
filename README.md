# Adaptix direct_https profile-loader research snapshot

这是一个**去敏后的私有研究快照**，主要保存最近围绕 `direct_https` agent、`profile-only loader`、`DHPL1/DHPLE2` 容器、以及相关测试脚本做过的源码与说明。

## 这个仓库包含什么

- `AdaptixServer/extenders/direct_https_agent/`
  - direct_https agent 的主要源码与插件层逻辑
- `research/memory-loader-lab/`
  - 内存加载实验、profile-only loader、容器打包脚本、第三方内存加载实现裁剪版
- `scripts/`
  - 自动化构建、启动、验证、内存扫描、差分辅助脚本
- `docs/`
  - 去敏后的研究总结、构建链路、阶段性结论

## 这个仓库不包含什么

- 本地运行时 `dist/`
- 原始 `reports/` 全量证据
- Windows 落地样本、生成的 loader / payload 二进制
- 本地账号、密码、token、主机 helper、环境私钥

## 当前版本重点

1. 从“完整 DLL 加密后下发”逐步转到“最小元数据容器 + 手动映射”。
2. 增加 profile-only loader，运行时不再依赖完整 export table 去找 `RunAgentDll`。
3. 外层容器保护从 XOR 演进到 PBKDF2 + salt + AES-256-GCM。
4. 研究了 PE header 在内存中的痕迹，并验证了 header scrub / profile-only 方案。

## 使用前需要先配置

- 你自己的 Adaptix API 地址、用户名、密码
- 你自己的 Windows 测试机 SSH/WMI/计划任务链路
- 你自己的发布目录 / HTTP 文件服务目录
- 你自己的 key / passphrase

默认占位值都已经改成 placeholder，请先按你的环境替换。

## 推荐阅读顺序

1. `docs/research-summary.md`
2. `docs/build-run-overview.md`
3. `docs/evidence-summary.tsv`
4. `research/memory-loader-lab/README.md`

