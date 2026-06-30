# 去敏说明

为了避免把本地环境信息直接推上 GitHub，这个快照做了下面几类处理：

1. 删除未必要的原始实验报告与落地二进制。
2. 删除 build/、reports/、dist/、Windows 落地文件。
3. 把本地绝对路径改成 repo 相对路径或占位值。
4. 把测试机 IP、C2 地址、默认 key、默认密码改成 placeholder。
5. 保留源码和研究逻辑，去掉本地运行时私有上下文。

如果你要在自己的环境里跑：

- 先检查 `scripts/` 和 `research/memory-loader-lab/` 里的 placeholder
- 再填入你自己的 API / Windows / 发布路径配置
