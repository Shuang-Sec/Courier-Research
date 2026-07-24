# WPP/WPS 实际加载 DLL 证据

## 结论

2026-07-23 21:33（Asia/Shanghai）通过 Windows 靶机的只读 PowerShell 模块枚举检查正在运行的 WPS 进程。本次快照发现 3 个 `wps.exe` 进程，全部加载：

```text
...\office6\krpt.dll
```

模块列表没有 `krpt.agent.dll` 记录。因此，本次实时快照中真正作为 WPS 宿主入口发挥作用的是 `krpt.dll`。旧别名属于历史候选的同字节副本，不是第二套 Agent。

## 实时模块枚举摘要

```text
ProcessCount: 3

wps PID <PID_A>  Responding=True  ModuleName=krpt.dll
  FileName=...\office6\krpt.dll

wps PID <PID_B>  Responding=True  ModuleName=krpt.dll
  FileName=...\office6\krpt.dll

wps PID <PID_C>  Responding=True  ModuleName=krpt.dll
  FileName=...\office6\krpt.dll
```

本次查询没有返回 `wpp.exe` 进程，也没有返回 `krpt.agent.dll` 模块。它证明的是当前运行快照的实际模块路径，不替代其他版本的历史记录。

## 对构建策略的影响

旧候选的构建过程曾执行过：

```bash
cp -f "$OUT/krpt.dll" "$OUT/krpt.agent.dll"
```

后续构建脚本已经移除这一步，并且会清理输出目录中旧候选遗留的别名。后续部署、静态扫描和 SHA-256 校验对象只包含 `cache.dat` 与 `krpt.dll`。

## 证据边界

- 静态部署记录只能证明某个文件被复制到 WPS 目录并通过扫描。
- 本文件的模块列表来自运行中的进程，是判断“哪个文件实际被加载”的直接证据。
- 当前 direct_https Agent 的业务代码仍来自 loader 从 `cache.dat` 解密和映射的 profile 内容；`krpt.dll` 是宿主接入和 loader 启动入口。
