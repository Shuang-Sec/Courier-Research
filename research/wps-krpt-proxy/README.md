# WPS/WPP `krpt.dll` 代理层

这个目录保存当前 WPP/WPS 集成所需的宿主代理层源码和构建入口。它位于整个链路的最外层：WPP/WPS 按原来的模块名加载 `krpt.dll`，代理 DLL 保留原始导出转发，同时启动内置的 DHPL loader。

## 运行链路

```text
WPP/WPS
  -> krpt.dll!DllMain
  -> start_agent_once()
  -> agent_loader_thread()
  -> dhpl_loader_main()
  -> 读取同目录 cache.dat
  -> 解密并映射 profile-only 容器
  -> RunAgentDll()
  -> AgentMain()
```

## 文件说明

| 文件 | 作用 |
|---|---|
| `krpt_proxy_agent.c` | 带诊断日志的代理 DLL 入口；创建线程并调用 loader |
| `krpt_proxy_agent_nodiag.c` | 关闭诊断输出的代理入口 |
| `gen_krpt_def.py` | 读取原始 `krpt_orig.dll` 导出表，生成 forwarder `.def` |
| `build-krpt-proxy.sh` | 构建带 loader 诊断的 x64 `krpt.dll` |
| `build-krpt-proxy-nodiag.sh` | 构建精简诊断版 x64 `krpt.dll` |

## 构建输入

原始厂商 DLL 和最终 `cache.dat` 是每个测试环境独立的外部输入，本仓库只保留构建代码。构建前设置：

```bash
export REAL_DLL=/path/to/preserved/krpt_orig.dll
export CACHE_DAT=/path/to/preserved/cache.dat
```

在仓库根目录执行：

```bash
./research/wps-krpt-proxy/build-krpt-proxy.sh
```

默认输出目录为 `research/wps-krpt-proxy/out-krpt/`，该目录属于本地构建输出。脚本通过环境变量 `REPO_ROOT`、`ML_ROOT`、`OUT`、`REAL_DLL` 和 `CACHE_DAT` 支持不同实验目录。

当前输出策略只保留 `krpt.dll`。旧候选曾把它复制为 `krpt.agent.dll`，但 2026-07-23 的 WPS 实时模块枚举显示运行中的 `wps.exe` 全部加载 `krpt.dll`，没有加载旧别名；因此后续构建脚本会清理输出目录中的旧别名，不再复制或发布它。

## 关键实现点

1. `DllMain` 只做轻量初始化和线程创建，复杂工作放到 loader 线程。
2. `GetModuleFileNameA` 定位当前 DLL，再从同一目录寻找 `cache.dat`。
3. 编译 loader 时使用 `-Dmain=dhpl_loader_main`，把 loader 的命令行入口链接进代理 DLL。
4. `.def` 文件把原始 `krpt.dll` 导出转发到并列保存的 `krpt_orig.dll`。
5. 诊断版通过 `PROFILE_ONLY_DIAG` 写出阶段标记，便于区分“宿主加载”“容器解密”“映射完成”和“AgentMain 进入”。

## 关联源码

- `research/memory-loader-lab/src/loader_profile_only.c`
- `research/memory-loader-lab/pack_profile_container.py`
- `research/memory-loader-lab/src/direct_https_dll_entry.cpp`
- `AdaptixServer/extenders/direct_https_agent/src_beacon/beacon/MainAgent.cpp`

最终候选的文件大小和 SHA-256 位于：

`docs/evidence/2026-07-21-wpp-wps-f0-ps-encoding/ARTIFACTS-AND-RUNS.md`
