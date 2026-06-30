# baseline-2026-06-30

## 这版是什么

这是一次 **去敏后的本地研究基线导出**，核心对应本地 `local-baseline-2026-06-30-profile-loader-dhple2` 这一版的稳定检查点。

这次 release 不是完整运行环境镜像，而是一个：

- source-only
- doc-first
- 可回溯
- 可继续整理

的私有研究快照。

---

## 本次 release 保留了什么

### 1. direct_https agent 相关源码

保留了 `AdaptixServer/extenders/direct_https_agent/`，包括：

- Go 插件层
- beacon 源码
- 命令与打包逻辑
- 配置与模板

### 2. memory-loader-lab 相关源码

保留了 `research/memory-loader-lab/`，包括：

- MemoryModule / MemoryModulePP_Lite 研究代码
- profile-only loader
- 容器打包脚本
- DLL payload 构建辅助脚本
- 第三方 loader 裁剪副本

### 3. 自动化脚本

保留了 `scripts/`，包括：

- build / regenerate / publish / launch
- callback / hello / command-surface 验证
- 内存扫描与静态差分辅助

### 4. 去敏后的总结文档

保留了 `docs/` 下的：

- 研究总结
- 构建/运行链路
- 证据摘要
- 去敏说明
- 源基线说明

---

## 本次 release 刻意去掉了什么

为了避免把本地环境信息和强绑定产物直接放进 GitHub，这次 release 没有保留：

- 本地运行时 `dist/`
- 原始 `reports/` 证据树
- Windows 落地样本
- 本地构建产物 `*.exe / *.dll / *.bin / *.dat`
- API 密码、token、内网地址、主机 helper、私钥
- 本地绝对路径和默认环境绑定参数

---

## 当前版本关注点

这一版对应的主要研究结论是：

1. 已经把 `direct_https` 的源码、构建链和重新生成链梳理清楚。
2. 内存加载研究已经从“完整 DLL 还原”推进到“最小元数据容器 + 专用 loader”。
3. 外层容器保护已经从 XOR 演进到 `PBKDF2 + salt + AES-256-GCM`。
4. PE header 的内存痕迹问题已经进入结构性处理阶段。

---

## 推荐怎么使用这个 release

建议把这版当成：

- 研究归档版本
- 代码审阅版本
- 文档回溯版本
- 后续继续清理和整理的基线版本

如果后面还要追加 release 资产，优先建议放：

- 文档包
- hash / evidence summary
- 非可执行的结构说明文件

默认不建议直接上传环境绑定的可执行样本。
