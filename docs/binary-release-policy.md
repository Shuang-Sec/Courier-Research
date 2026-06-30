# 二进制 release 策略（binary release policy）

这份文档的目标，是把下面这件事彻底固定下来：

> **哪些文件可以放 GitHub release，哪些文件不要放？**

因为这个仓库是一个**去敏后的长期私有研究仓库**，所以 release 的重点不是“把所有东西都挂上去”，而是：

- 既方便以后回看
- 又不把本地运行环境和强绑定产物直接带出去

---

## 1. 默认原则

### 原则 A：文档优先，源码优先

release 默认优先保留：

- tag
- 源码快照
- 文档包
- 去敏后的摘要文件

### 原则 B：二进制谨慎，不默认上传

任何满足以下任一条件的二进制，都默认**不上传**：

- 强依赖当前本地运行环境
- 含明显运行时特征字符串
- 含测试拓扑信息
- 含容器格式细节或结构元数据
- 直接就是 Windows 可执行样本

---

## 2. 当前 allowlist（允许进入 release 的内容）

下面这些内容，默认允许：

### A. 文档类

- `README.md`
- `CHANGELOG.md`
- `docs/*.md`
- `docs/*.tsv`

### B. 源码类

- GitHub 自带 source zip / tar.gz
- 仓库中的源码目录本身

### C. 非可执行文档包

例如：

- `baseline-2026-06-30-docs.zip`

这类包应该满足：

- 不含 `*.exe` / `*.dll` / `*.bin` / `*.dat`
- 不含原始 `reports/`
- 不含本地私有配置

---

## 3. 当前 denylist（默认禁止进入 release 的内容）

下面这些内容，当前默认**不要上传到 release**。

### A. 直接可执行样本

- `*.exe`
- `*.dll`

例如：

- `loader_profile_only.x64.exe`
- `loader_profile_only_diag.x64.exe`
- `loader_agentdll_mmpp_lite.x64.exe`
- `direct_https_profile.x64.dll`

### B. payload / container / 加密材料

- `*.bin`
- `*.dat`
- `cache.dhpl`

原因：

- 虽然它们不一定是直接双击运行的最终程序，但已经非常接近真实运行材料。

### C. 编译中间产物

- `*.o`
- `*.a`
- `*.pdb`

### D. 构建日志 / 运行日志 / 原始元数据

- `*.log`
- `cache.dhpl.meta.json`
- `profile-release-variants-sha256.txt`
- 各类 build log / rebuild log

原因：

- 这些文件看起来不是“危险的可执行文件”，但往往能泄露：
  - 编译结构
  - 变体命名
  - 容器内部字段
  - 本地研究路径

---

## 4. 为什么当前二进制不建议放 release

这是基于实际检查得出的，不是抽象规则。

### 4.1 loader 二进制里仍然能看到明显字符串

例如实际检查到过：

- `DHPL_KEY`
- `DHPL_KEY_FILE`
- `BCryptDeriveKeyPBKDF2`
- `DHPL1-AES256-GCM-PBKDF2-SHA256-v2`

有些版本里还看得到默认 key 占位或诊断标记。

### 4.2 payload DLL 里仍然能看到运行相关字符串

例如实际检查到过：

- `wininet.dll`
- `Mozilla/5.0`
- `RunAgentDll`
- 测试时用过的路径/占位字符串

### 4.3 容器及 meta 文件也会暴露结构信息

例如：

- section 名
- RVA
- image size
- import / reloc / TLS 数量
- `run_agent_rva`

所以它们虽然不是 exe，但依然不适合默认放 release。

---

## 5. 一个简单判断法

如果你犹豫某个文件能不能放 release，就按下面 5 个问题判断：

### 问题 1：它是不是可执行文件？

如果是：

- 默认不放

### 问题 2：它是不是 payload/container/loader 的直接运行材料？

如果是：

- 默认不放

### 问题 3：它里面会不会暴露结构细节、路径、字符串、测试材料？

如果会：

- 默认不放

### 问题 4：它是不是仅用于“阅读和归档”？

如果是：

- 大概率可以放

### 问题 5：我把它挂到 release 后，是否会把仓库从“研究归档”变成“运行材料分发点”？

如果会：

- 不建议放

---

## 6. 推荐的 release 资产类型

以后这个私有仓库如果继续打 release，建议优先上传：

### 推荐

- 文档包
- 去敏后的结构摘要
- hash/evidence summary
- 源基线说明
- changelog 快照

### 不推荐

- loader 二进制
- payload DLL
- 容器文件
- 原始 meta 文件
- build log
- 本地测试用样本

---

## 7. 上传前检查清单

每次想把某个资产挂到 release 之前，建议最少做这 6 步：

1. `file` 看文件类型
2. `strings` 看明显字符串
3. 检查是否含本地路径 / 内网地址 / 默认 key
4. 检查是否属于运行材料
5. 检查是否属于中间产物
6. 再决定是否进入 release

---

## 8. 当前仓库的结论

就当前这个私有仓库而言，推荐策略是：

### 可以放

- `baseline-2026-06-30-docs.zip`
- 所有文档与源码 tag

### 不要放

- `loader_profile_only*.exe`
- `loader_agentdll_mmpp_lite.x64.exe`
- `direct_https_profile.x64.dll`
- `cache.dhpl`
- `cache.dhpl.meta.json`
- `.o / .a / log / build summary`

---

## 9. 一句话总结

这个仓库的 release，应该更像：

- **研究归档**
- **文档化基线**
- **源码快照**

而不是：

- **本地运行材料分发点**

