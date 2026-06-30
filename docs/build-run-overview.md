# 源码 -> 构建 -> 生成产物 -> 启动 的简化链路

## 1. direct_https 相关源码

核心目录：

- `AdaptixServer/extenders/direct_https_agent/`
- `research/memory-loader-lab/`
- `scripts/`

## 2. 大致分层

### A. agent/beacon 层

负责：

- 初始化
- HTTP/HTTPS 通信
- 命令执行
- 文件功能
- `RunAgentDll` 最终进入的主体逻辑

### B. packer/container 层

负责：

- 读取 DLL
- 离线提取 section / reloc / import / TLS / exception / RVA
- 生成容器（如 `DHPL1`）
- 再做外层加密封装（如 `DHPLE2`）

### C. loader 层

负责：

- 读取容器
- 派生密钥
- 解密容器
- 申请内存
- 拷贝 section
- 修复 reloc/import
- 调用 `DllMain`
- 最后进入 `RunAgentDll`

### D. 自动化脚本层

负责：

- 构建
- 生成样本
- 发布到测试目录
- 远程启动
- 轮询 callback / hello / 命令矩阵
- 做内存扫描与结果归档

## 3. 你真正需要记住的一点

**改源码 != 新样本已经生成。**

中间一般还要经过：

1. 重新 build
2. 如果改的是插件 / 服务端逻辑，还要重启对应 runtime
3. 重新生成 payload / container
4. 把新的 loader / payload 下发到 Windows
5. 再启动测试

