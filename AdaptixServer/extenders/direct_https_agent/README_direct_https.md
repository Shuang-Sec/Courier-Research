# direct_https_agent

`direct_https_agent` 是 HTTPS-only 的 Adaptix agent，当前版本把底层源码和运行产物收敛到 HTTPS 回连、`cmd`/`powershell` 执行、文件增删改查、上传下载。

## 暴露功能

- `cmd`：通过 `cmd.exe /d /c` 执行命令并回显。
- `powershell`：通过 `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command` 执行命令并回显。
- 文件功能：`pwd`、`cd`、`ls`、`cat`、`cp`、`mv`、`mkdir`、`rm`、`upload`、`download`。

## 开发期辅助

以下命令仅作为开发/调试辅助暂留，最终验收前可删除或隐藏：

- `hello`：链路与命令表刷新验证。
- `jobs kill`：停止长时间运行的 `cmd`/`powershell` job。
- `terminate thread/process`：退出 agent 线程或进程。

## 命令与 opcode 边界

- `cmd`、`powershell` 在 server 侧都归一为 `COMMAND_PS_RUN`，但 command line 明确带 `cmd.exe /d /c` 或 `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command` 前缀。
- 文件能力 opcode 保留为：`COMMAND_PWD`、`COMMAND_CD`、`COMMAND_LS`、`COMMAND_CAT`、`COMMAND_MKDIR`、`COMMAND_RM`、`COMMAND_COPY`/`COMMAND_CP`、`COMMAND_MV`、`COMMAND_DOWNLOAD`、`COMMAND_UPLOAD`。
- `COMMAND_SAVEMEMORY` 仅服务于 `upload` 的分片传输，不在 `ax_config.axs` 中暴露为 operator 命令。
- `COMMAND_DOWNLOAD_STATE` 仅用于下载状态上报，不作为 server→agent 的可达控制 handler。
- 当前 v1 已注册 `disks`；后台 job 控制、terminate 和下载状态控制等未纳入 release 的历史接口不作为 operator 命令暴露。

## 构建

```bash
export REPO_ROOT="$(git rev-parse --show-toplevel)"
cd AdaptixServer/extenders/direct_https_agent
export PATH="$REPO_ROOT/tools/go/bin:$REPO_ROOT/tools/mingw/usr/bin:$PATH"
export GOCACHE="$REPO_ROOT/tools/gocache"
export GOPATH="$REPO_ROOT/tools/gopath"
export GOPROXY=off
make clean && make
```

构建产物：

```text
AdaptixServer/extenders/direct_https_agent/dist/agent_direct_https.so
AdaptixServer/extenders/direct_https_agent/dist/objects_http/
```

运行部署目录：

```text
dist/extenders/direct_https_agent/
```

运行 profile：

```text
dist/profile-direct-https.yaml
```
