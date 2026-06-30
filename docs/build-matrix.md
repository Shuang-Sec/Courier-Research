# 构建矩阵（build matrix）

这份文档专门解决一个经常出错的问题：

> **我改了代码之后，到底要不要重编？要不要重启？要不要重新生成 payload？要不要把 Windows 上的旧样本换掉？**

如果这个问题没搞清楚，就很容易出现：

- 代码改了，但测试的还是旧样本
- loader 改了，但容器没重做
- Go 插件改了，但 runtime 没重启
- beacon 改了，但 Windows 上跑的还是旧 exe

---

## 1. 先记住一条总原则

**改源码 != 新样本已经生效。**

中间通常至少还隔着下面几步中的几步：

1. 重新构建
2. 同步到运行时目录
3. 重启 runtime / teamserver
4. 重新生成 payload / container
5. 替换 Windows 侧旧文件
6. 再重新启动测试

---

## 2. 总矩阵

| 你改了什么 | 典型文件 | 要不要重编 | 要不要重启 runtime | 要不要重新生成 payload/container | 要不要重新下发 Windows 文件 | 备注 |
|---|---|---:|---:|---:|---:|---|
| direct_https Go 插件层 | `pl_main.go` `pl_packer.go` `pl_utils.go` | 是 | 是 | 通常要 | 如果最终样本依赖新生成产物，则要 | 影响命令注册、profile 生成、payload 生成 |
| direct_https beacon/C++ 层 | `MainAgent.cpp` `ConnectorHTTP.cpp` `Commander.cpp` | 是 | 如果产物由 runtime 生成，通常要 | 是 | 是 | 这是最常见的“源码改了但样本没更新”来源 |
| direct_https 配置/UI 脚本 | `ax_config.axs` `config.yaml` | 视情况 | 通常要 | 通常要 | 如果重新生成了样本，则要 | 影响参数、UI、插件行为 |
| Memory loader 源码 | `loader_profile_only.c` `loader_agentdll_mmpp_lite.c` | 是 | 否 | 否（除非容器格式也变） | 是 | loader 是单独的 Windows 侧程序 |
| 容器打包逻辑 | `pack_profile_container.py` | 否（脚本本身不需要编译） | 否 | 是 | 是 | 容器格式或内容变了，必须重打包 |
| DLL payload 构建逻辑 | `build_direct_https_profile_dll.py` | 否（脚本本身不需要编译） | 通常否 | 是 | 是 | 影响 `direct_https_profile.x64.dll` 的内容 |
| 第三方内存加载实现裁剪 | `third_party/MemoryModulePP_Lite/*` | 是 | 否 | 否（除非联动容器逻辑） | 是 | 会影响 loader 行为 |
| 只改文档 | `docs/*` `README.md` | 否 | 否 | 否 | 否 | 只影响说明，不影响实际运行 |
| 只改 release 说明/仓库治理文档 | `CHANGELOG.md` `docs/*.md` | 否 | 否 | 否 | 否 | 只影响仓库维护 |

---

## 3. 按路径拆解

### 3.1 改 direct_https agent 源码时

典型目录：

```text
AdaptixServer/extenders/direct_https_agent/
```

你通常需要做：

1. 重建插件 / beacon 相关产物
2. 同步到对应 runtime 目录
3. 重启相关 runtime / teamserver
4. 重新生成新的 payload
5. 记录新样本 hash
6. 把新样本发到 Windows 再测

#### 结论

这是**必须把“源码改动”和“新样本重新生成”绑定在一起**的区域。

---

### 3.2 改 loader 时

典型目录：

```text
research/memory-loader-lab/src/
```

比如你改：

- `loader_profile_only.c`
- `loader_agentdll_mmpp_lite.c`

你通常需要做：

1. 重编 loader
2. 替换 Windows 侧旧 loader
3. 用新的 loader 去跑已有容器，或者再配合新容器一起测

#### 结论

- **不一定要重启 Adaptix runtime**
- **但一定要重新替换 Windows 上的 loader**

---

### 3.3 改容器打包逻辑时

典型文件：

```text
research/memory-loader-lab/pack_profile_container.py
```

你通常需要做：

1. 重新构造新的容器文件
2. 记录新容器 hash
3. 替换 Windows 侧旧容器
4. 用现有或新 loader 测试

#### 结论

这个场景最容易出现：

- loader 没变
- 但容器已经变了
- Windows 上还在拿旧 `cache.dhpl`

所以**只要 packer 变了，就默认重打包并替换 Windows 侧文件。**

---

### 3.4 改 DLL payload 构建逻辑时

典型文件：

```text
research/memory-loader-lab/build_direct_https_profile_dll.py
```

你通常需要做：

1. 重新生成 DLL payload
2. 如果后面还要 pack container，就继续重打包
3. 如果后面还要配合 loader，就重新替换 Windows 侧的容器/样本

#### 结论

这类改动经常会改变：

- profile
- listener 数据
- embed 的配置
- `RunAgentDll` 对应的最终 payload 内容

所以**默认要重新生成 DLL，再重新打包容器。**

---

## 4. 最常见的 4 个误区

### 误区 1：我改了代码，所以 Windows 上跑的一定是新的

不对。  
Windows 上很可能还是旧的 loader / 旧容器 / 旧 exe。

### 误区 2：我重编了 loader，所以 payload 一定也更新了

不对。  
loader 和 payload/container 是两条链，可能只更新了一条。

### 误区 3：我改了 Go 层，不重启 runtime 也没关系

通常不对。  
如果当前运行的是旧 runtime/plugin 映射，就会出现“源码是新的，运行时还是旧的”。

### 误区 4：我改了 packer，但没必要重新打包

不对。  
只要 packer 改了，旧容器通常就不能代表新逻辑。

---

## 5. 最实用的判断表

你每次改完东西后，可以直接问自己：

### 我改的是：

#### A. direct_https agent 逻辑？

那就做：

- 重编
- 同步 runtime
- 重启
- 重新生成 payload
- 重测 Windows

#### B. loader 逻辑？

那就做：

- 重编 loader
- 替换 Windows loader
- 重测

#### C. packer / container 逻辑？

那就做：

- 重新打包容器
- 替换 Windows 容器
- 重测

#### D. 文档？

那就：

- 不需要重编
- 不需要重启
- 只需要提交仓库

---

## 6. 推荐操作顺序

以后建议你每轮都尽量按这个顺序走：

1. 明确你改的是哪一层
2. 对照本矩阵确定动作
3. 重新生成新的产物
4. 记录 hash
5. 替换 Windows 侧旧文件
6. 再启动测试
7. 把结果写回文档/CHANGELOG

这样可以显著减少“测了半天其实测的是旧东西”的问题。

