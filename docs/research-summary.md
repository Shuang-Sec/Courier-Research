# 研究总结（去敏版）

## 1. 近期主线

这一阶段主要做了三条线：

1. **direct_https agent 结构梳理**
   - 先把 agent 的源码、命令流、check-in、打包链路梳理清楚。
2. **查杀触发点定位**
   - 前期围绕初始化、WinINet、请求形态、启动上下文做了多轮单变量实验。
3. **内存加载与容器演进**
   - 从最初的 MemoryModulePP_Lite + XOR，逐步演进到 profile-only loader + DHPL1，再到 DHPLE2（PBKDF2 + salt + AES-GCM）。

## 2. 当前架构结论

### 2.1 旧链路

旧链路更像：

- 生成完整 DLL
- 直接加密/包裹
- Windows loader 解密出完整 PE
- 再在内存里做手动映射

这类做法的问题是：

- 解密后阶段很像“完整 PE 还原”
- 内存里也更容易看到明显的 PE 痕迹
- 运行时还可能依赖 export table 做函数定位

### 2.2 当前链路

当前快照保存的是“更专用”的思路：

- Linux 侧先把 DLL 离线拆成只保留必要运行元数据的容器
- 容器里保留 section / reloc / import / TLS / exception / RunAgentDll RVA 等最小必要信息
- Windows 侧 loader 读取容器后直接按这些元数据映射
- 运行时不再依赖完整 PE header / export table
- 外层容器保护升级为 PBKDF2 + salt + AES-256-GCM

## 3. 阶段性结果

- 已经完成从 XOR 容器到 AES-GCM 容器的升级。
- 已经完成 `RunAgentDll` 从运行时导出查找转向离线预解析 RVA。
- 已经把 loader 做成更偏“专用 payload loader”的方向，而不是通用 PE loader。
- 已经有针对 PE header 内存痕迹的处理与验证思路。

## 4. 为什么这里不直接放原始报告

原始报告里包含：

- 本地绝对路径
- 内网测试地址
- Windows 落地目录
- 本地运行拓扑与证据树

因此这里保留的是**源码 + 去敏说明 + 证据摘要**，原始证据继续留在本地离线保存。
