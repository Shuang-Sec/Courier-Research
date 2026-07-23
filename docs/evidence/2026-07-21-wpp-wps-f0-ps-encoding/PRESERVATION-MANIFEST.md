# 最新 WPP/WPS direct_https 版本重点留存清单

## 1. 这份留存解决什么问题

这份目录保存的是当前已经完成 WPP/WPS 功能回归的 release 版本。它把两类内容放在同一个快照下：

1. 精确到 Git tag 的源码归档。
2. 已经编译、打包、扫描和部署验证过的最终文件。

这样，后续继续开发时，可以明确区分“当前已验证版本”和“下一轮实验版本”。当前快照的主版本标识如下：

| 项目 | 值 |
|---|---|
| release tag | release-wpp-functional-v1 |
| 源码提交 | 72e54efee51ee70445344a81c4580142a505b0e2 |
| 分支 | feature/direct-https-minimal-agent |
| 候选目录 | LOCAL_CANDIDATE_ROOT |
| 留存日期 | 2026-07-21 |
| 功能范围 | hello、cmd、powershell、pwd、cd、ls、cat、mkdir、rm、cp、mv、disks、upload、download |

这里的“留存”可以理解成给当前版本拍一张带指纹的快照。文件内容、源码提交和 SHA-256 都被记录下来，后面拿到同名文件时，可以先用哈希判断它是否仍然是这一版。

## 2. 留存目录结构

~~~text
preserved-latest-20260721/
├── PRESERVATION-MANIFEST.md
├── PRESERVED-SHA256SUMS
├── source/
│   ├── AdaptixC2-release-wpp-functional-v1.tar.gz
│   ├── source-commit.txt
│   └── source-git-show.txt
└── artifacts/
    └── release-wpp-functional-v1/
        ├── cache.dat
        ├── agent_direct_https.so
        ├── krpt.dll
        ├── krpt.agent.dll
        ├── profile_dll/
        ├── build-logs/
        ├── scan-and-deploy.sh
        ├── release-callback-monitor.py
        ├── MANIFEST.md
        └── SHA256SUMS
~~~

## 3. 源码是怎样保存的

source/AdaptixC2-release-wpp-functional-v1.tar.gz 由下面这个精确 tag 生成：

~~~text
release-wpp-functional-v1^{} = 72e54efee51ee70445344a81c4580142a505b0e2
~~~

归档包含该提交里 Git 已跟踪的完整 AdaptixC2 源码。重点代码位于：

~~~text
AdaptixServer/extenders/direct_https_agent/
~~~

源码归档没有把工作树里后来产生的临时日志和未跟踪进度文档混入 release 源码。那些历史材料继续保留在原仓库和候选报告目录中；当前 release 的可构建代码以 Git tag 为准。

源码归档的文件信息：

| 项目 | 值 |
|---|---|
| 文件 | source/AdaptixC2-release-wpp-functional-v1.tar.gz |
| 大小 | 39,060,314 字节 |
| SHA-256 | 075ebb69248a2ebe0d315bef89d1fc0ea21a2d259b327b8c7963b7c6a8f7ff04 |
| 生成方式 | git archive |

source/source-commit.txt 保存 tag、提交、分支、上游对照引用和改造前基线。source/source-git-show.txt 保存该 release 提交的摘要和变更文件统计。

## 4. 构建文件是怎样保存的

artifacts/release-wpp-functional-v1/ 是最终 release 包的完整复制品，不只是几个 DLL。里面同时保存了：

### 4.1 运行所需文件

| 文件 | 用途 |
|---|---|
| cache.dat | profile 和连接配置的打包文件 |
| agent_direct_https.so | Adaptix 服务端运行时插件 |
| krpt.dll | WPS 侧代理相关文件 |
| krpt.agent.dll | WPS 侧 agent 代理文件 |
| profile_dll/direct_https_profile.x64.dll | x64 profile DLL |
| profile_dll/direct_https_profile.x64.bin | profile 的容器形式 |
| profile_dll/profile.bin | profile 内容 |

### 4.2 复跑与审计文件

| 文件或目录 | 作用 |
|---|---|
| build-logs/ | Go、C++、profile、cache、代理构建日志 |
| scan-and-deploy.sh | 部署和 Kaspersky 门禁脚本 |
| release-callback-monitor.py | 720 秒回连存活监控程序 |
| MANIFEST.md | release 说明和核心哈希 |
| SHA256SUMS | release 包内部的逐文件哈希 |

## 5. 核心文件哈希

下表是本版本最需要重点核对的文件。完整文件清单在 PRESERVED-SHA256SUMS 和 artifacts/release-wpp-functional-v1/SHA256SUMS 中。

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| cache.dat | 79,896 | 5c89811ade759d5c1c6cc25f153357931f66320160da63e77c055c7d2193961b |
| krpt.dll | 50,688 | b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac |
| krpt.agent.dll | 50,688 | b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac |
| agent_direct_https.so | 5,555,176 | d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779 |
| direct_https_profile.x64.dll | 79,360 | 68a869ea61661679b80e7960e0d2ddcbef3c71e0fb9f7d59acbeb01af051860e |
| direct_https_profile.x64.bin | 79,360 | ddedc93991527f2c08a4bb57e934d3023fe095dd7ac13cae59ec13c84126c5c7 |
| profile.bin | 275 | a2ab53a8599ec53f841b29eda26b44ca454a577c63d295b0d019aa6f01544df9 |

## 6. 哈希校验结果

留存时完成了两层校验：

1. 先在复制出来的 release 包目录内执行原有 SHA256SUMS，包内所有文件均显示 OK。
2. 再在留存根目录生成 PRESERVED-SHA256SUMS，覆盖 source/ 和 artifacts/ 下的所有文件。

第二层清单本身不包含在自己的哈希列表内，避免出现“哈希文件把自己算进去”的循环。文档和说明文件属于人类阅读材料，源码归档和构建包属于机器验证材料，两者分开保存。

完整复核命令：

~~~bash
cd LOCAL_CANDIDATE_ROOT/preserved-latest-20260721
sha256sum -c PRESERVED-SHA256SUMS
cd artifacts/release-wpp-functional-v1
sha256sum -c SHA256SUMS
~~~

复核时，两个命令都应输出对应文件的 OK。若某个文件哈希变化，先把它标记为新候选，再重新构建和验证，避免把新旧版本混在同一个 release 名称下。

## 7. 当前版本的验证证据

这次留存对应的总报告：

- LOCAL_CANDIDATE_ROOT/RESULT.md
- LOCAL_CANDIDATE_ROOT/IMPLEMENTATION-OVERVIEW.md
- LOCAL_CANDIDATE_ROOT/release-wpp-functional-v1/MANIFEST.md
- LOCAL_CANDIDATE_ROOT/release-survival-final.txt

三次独立部署的结果目录：

- release-run-2b：WPP/WPS 回连 65/65，功能矩阵 17/17，新鲜 Qscan 为 3548/0/0。
- release-run-3：WPP/WPS 回连 60/64，功能矩阵 17/17，新鲜 Qscan 为 3572/0/0。
- release-run-4：WPP/WPS 回连 65/65，功能矩阵 17/17，新鲜 Qscan 为 3572/0/0。

这里的 Qscan 数字顺序是 processed / detected / errors。三轮的静态扫描、系统内存扫描和新鲜 Qscan 均为 detected 0、errors 0、返回码 0。WPP/WPS 进程保持 Responding，scratch 目录和 C:\Users\Public\direct-https-job-*.out 均完成清理。

用户补充确认：自己在靶机上的功能测试已经基本完成。本目录保存的是实现、构建和已有自动化回归的机器证据；用户侧手工验证可作为当前版本已经具备实际可用性的补充确认。

## 8. 对照基线

上游 origin/main 的提交是：

~~~text
a4b80bf370f704d6843e69433bfb5c06274f57df
~~~

这个上游分支包含官方 Adaptix 的 beacon_agent，但没有 direct_https_agent 目录。因此“与原版 Adaptix 的比较”采用两层基线：

1. 官方 beacon_agent：比较通用 Adaptix agent 的结构、命令分发、匿名管道 job 和 HTTP connector。
2. 本项目改造前 direct_https：提交 a199bc15528b015cb6ae1a2affc6ac0ec5c80ad8，比较这条 direct_https 路径从早期协议和 hello/pwd 版本到当前功能 release 的真实变化。

详细对比见同目录的 INNOVATIONS-VS-ORIGINAL-ADAPTIX.md。

## 9. 后续版本管理建议

当前目录作为 release 快照使用。后续开发建议遵循下面的记录方式：

1. 从 release-wpp-functional-v1 创建新的候选分支。
2. 每次只引入一个主要变量，并为候选建立新的 commit 和 tag。
3. 新构建产物进入新的候选报告目录，保留对应的构建日志和哈希。
4. 新候选通过完整门禁后，再生成新的独立留存目录。
5. 当前快照中的源码归档、release 包和哈希清单保持原样，作为后续回归基线。

这样做的好处是：出现崩溃、功能回归或扫描结果变化时，可以直接定位到具体候选，而不是从多个覆盖复制的文件中猜测版本。
