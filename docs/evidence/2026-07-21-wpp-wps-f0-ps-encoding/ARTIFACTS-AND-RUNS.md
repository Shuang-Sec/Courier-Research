# 最终候选文件指纹与运行摘要

## 源码和构建身份

```text
source_commit = 72e54efee51ee70445344a81c4580142a505b0e2
local_tag     = release-wpp-functional-v1
candidate     = wpp-wps-f0-ps-encoding-20260721-165405
```

## 最终候选主要文件

> 本页的制品表记录的是 2026-07-21 历史候选，因此仍列出当时生成的 `krpt.agent.dll`。实时模块证据已经确认 WPS 加载的是 `krpt.dll`；后续候选只生成、部署和扫描 `krpt.dll`。

| 文件 | 大小 | SHA-256 |
|---|---:|---|
| `cache.dat` | 79,896 bytes | `5c89811ade759d5c1c6cc25f153357931f66320160da63e77c055c7d2193961b` |
| `krpt.dll` | 50,688 bytes | `b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac` |
| `krpt.agent.dll` | 50,688 bytes | `b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac` |
| `direct_https_profile.x64.dll` | 79,360 bytes | `68a869ea61661679b80e7960e0d2ddcbef3c71e0fb9f7d59acbeb01af051860e` |
| `direct_https_profile.x64.bin` | 79,360 bytes | `ddedc93991527f2c08a4bb57e934d3023fe095dd7ac13cae59ec13c84126c5c7` |
| `profile.bin` | 275 bytes | `a2ab53a8599ec53f841b29eda26b44ca454a577c63d295b0d019aa6f01544df9` |
| `agent_direct_https.so` | 5,555,176 bytes | `d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779` |

## Kaspersky 门禁

每次新鲜部署均完成以下检查：

| 门禁 | 结果 |
|---|---|
| `cache.dat` 静态扫描 | processed 1、detected 0、errors 0、return code 0 |
| `krpt.dll` 静态扫描 | processed 1、detected 0、errors 0、return code 0 |
| `krpt.agent.dll` 静态扫描 | processed 1、detected 0、errors 0、return code 0 |
| `Scan_System_Memory` | processed 1、detected 0、errors 0、return code 0 |
| 新鲜 `Scan_Qscan` | 三次均 detected 0、errors 0、return code 0 |

## 功能和存活

```text
registered_commands = 14
WPP full matrix       = 17/17
WPS full matrix       = 17/17
F0 main checks        = 10/10
disks                 = WPP 2/2, WPS 2/2
upload/download       = content and SHA-256 matched
callback window       = 720 seconds per run
minimum callbacks     = 6 per host per run
cleanup               = scratch absent, job output files absent
```

## 本地完整材料

完整运行材料保存在本地最终候选目录及其 `preserved-latest-20260721` 子目录。这个仓库只保存可阅读的源码和去敏证据摘要；重新核对时，以本文件的 SHA-256 和本地 `SHA256SUMS` 为交叉检查依据。
