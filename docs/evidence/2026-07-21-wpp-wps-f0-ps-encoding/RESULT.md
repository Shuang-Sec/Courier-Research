# WPP/WPS direct_https v6 candidate result

## Candidate

- Candidate: `wpp-wps-f0-ps-encoding-20260721-165405`
- Date: `2026-07-21`
- Source commit: `72e54efee51ee70445344a81c4580142a505b0e2`
- Local tags: `stage-F1-command-exec`, `stage-F2-file-crud`, `stage-F3-transfer`, `release-wpp-functional-v1`
- Listener: `HTTPS_LISTENER`
- Profile: x64, sleep `10s`, jitter `0`, beat dialect `2`, lite WinINet connector
- Result: final repeated F0-F3 release gates passed across three independent deployments; local release tag `release-wpp-functional-v1` is ready.
- Implementation overview: [IMPLEMENTATION-OVERVIEW.md](IMPLEMENTATION-OVERVIEW.md)
- Kaspersky pass-point analysis: [KASPERSKY-PASS-ANALYSIS.md](LOCAL_CANDIDATE_ROOT/KASPERSKY-PASS-ANALYSIS.md)

## Scope

The candidate covers the registered v1 command surface:

`hello`, `cmd`, `powershell`, `pwd`, `cd`, `ls`, `cat`, `mkdir`, `rm`, `cp`, `mv`, `disks`, `upload`, `download`.

The task envelope, LPT4/schema4 framing, native result bundle V4, command opcodes, and legacy result fallback remain unchanged. The implementation adds the file-backed process-output path, a final output drain before job cleanup, and UTF-16LE PowerShell file-output normalization to the agent OEM code page. The existing Go-side command argument trimming is retained so a packed trailing NUL does not become part of the redirected command line.

## Build

- x64 profile DLL and XOR container: [profile-build-ps-encoding.log](profile-build-ps-encoding.log)
- x86 object compilation: [x86-build.log](x86-build.log)
- Encrypted cache packaging: [cache-pack-ps-encoding.log](cache-pack-ps-encoding.log)
- WPP proxy build: [build-krpt-proxy-ps-encoding.log](build-krpt-proxy-ps-encoding.log)
- `git diff --check`: pass before commit and after staging
- Go `1.25.4` was run from an isolated toolchain. `go test ./...` passed in the `direct_https_agent` module. The AdaptixServer root module passes `go test -vet=off ./...`; its default `go test ./...` is blocked by pre-existing non-constant format-string vet diagnostics in `logs.*` calls. Raw output and the toolchain hash are in [Go build logs](build-logs/).

Build flags used by the profile stage include `DIRECT_HTTPS_LAZY_HTTP_SEND=1`, `DIRECT_HTTPS_LAZY_WININET_INIT=1`, `DIRECT_HTTPS_LITE_CONNECTOR=1`, `DIRECT_HTTPS_NO_API_HASHING=1`, `DIRECT_HTTPS_BEAT_DIALECT=2`, and the normal full command configuration.

## Artifact hashes

| Artifact | Size | SHA-256 |
|---|---:|---|
| `cache.dat` | 79,896 | `5c89811ade759d5c1c6cc25f153357931f66320160da63e77c055c7d2193961b` |
| `krpt.dll` | 50,688 | `b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac` |
| `krpt.agent.dll` | 50,688 | `b4bb6f1171cb80e9514c767110a3bb68c7e9a3688b9887f423d0fceb1cc46bac` |
| `direct_https_profile.x64.dll` | 79,360 | `68a869ea61661679b80e7960e0d2ddcbef3c71e0fb9f7d59acbeb01af051860e` |
| `direct_https_profile.x64.bin` | 79,360 | `ddedc93991527f2c08a4bb57e934d3023fe095dd7ac13cae59ec13c84126c5c7` |
| `profile.bin` | 275 | `a2ab53a8599ec53f841b29eda26b44ca454a577c63d295b0d019aa6f01544df9` |
| `agent_direct_https.so` | 5,555,176 | `d86807bff5a7e8e7ce146ce3b56b84a2400b42b3973c3d1f56c1973eefaa3779` |

The complete x86 object hash list is in [artifact-hashes-profile-ps-encoding.txt](artifact-hashes-profile-ps-encoding.txt); the complete artifact list is in [artifact-hashes-ps-encoding.txt](artifact-hashes-ps-encoding.txt).

## Kaspersky gates

All three artifact static scans processed one object, detected zero, reported zero errors, and returned code `0`:

- [static-scan-cache.dat.report.txt](static-scan-cache.dat.report.txt)
- [static-scan-krpt.dll.report.txt](static-scan-krpt.dll.report.txt)
- [static-scan-krpt.agent.dll.report.txt](static-scan-krpt.agent.dll.report.txt)

`Scan_System_Memory` was a fresh task from `17:02:41` to `17:02:42`, processed `1`, detected `0`, errors `0`, return code `0`: [kaspersky-memory.report.txt](kaspersky-memory.report.txt).

`Scan_Qscan` was a fresh task from `17:02:43` to `17:12:58`, processed `3,752`, detected `0`, errors `0`, return code `0`: [kaspersky-qscan.report.txt](kaspersky-qscan.report.txt). The deployment wrapper records both task gates as `PASS` in [deploy-scan.log](deploy-scan.log).

## Live command validation

- WPP main agent: `WPP_AGENT_ID`, `wpp.exe`, PID `10796`, all `17/17` scripted tasks completed.
- WPS main agent: `WPS_AGENT_ID`, `wps.exe`, PID `10740`, all `17/17` scripted tasks completed.
- Main command matrix: `10/10` checks passed, including `cmd`, PowerShell marker output, PowerShell location, and `pwd`: [functional-f0-main-matrix.json](functional-f0-main-matrix.json).
- `disks`: both WPP and WPS returned the actual entries `C: fixed (3)` and `D: cdrom (5)`. The result was cross-checked against the target's live `Win32_LogicalDisk` list: [functional-disks-v6.json](functional-disks-v6.json), [disks-host-v6.json](disks-host-v6.json).
- Combined surface result: [functional-surface-v6.json](functional-surface-v6.json).
- WPP full matrix: [wpp-live-full-baseline-result.json](wpp-live-full-baseline-result.json), [wpp-live-full-baseline-result.md](wpp-live-full-baseline-result.md).
- WPS full matrix: [wps-live-full-baseline-result.json](wps-live-full-baseline-result.json), [wps-live-full-baseline-result.md](wps-live-full-baseline-result.md).

The file regression created a unique scratch directory per host session, uploaded a 49-byte marker file, verified `ls` and `cat`, copied it, moved it, downloaded it, verified the local SHA-256, removed both remote files, returned to the WPS office directory, and removed the scratch directory.

Downloaded content matched the expected bytes for both hosts:

- WPP SHA-256: `256e87753f4c44cff00ca8a7ec4e5189c5e9110298d1bed84443fe9c79152cb0`
- WPS SHA-256: `3c553e0fa6d9ebdc1f023736b825f6c7bf17c396f17049912fa4f2ee05e264ae`

Hash evidence: [download-hash-v6.json](download-hash-v6.json).

## Cleanup and survival

The target-side post-run check found both scratch paths absent, no `C:\Users\Public\direct-https-job-*.out` files, and all observed `wpp`/`wps` processes with `Responding=true`: [process-survival-cleanup-v6.json](process-survival-cleanup-v6.json). The final post-matrix snapshot is [release-survival-final.txt](release-survival-final.txt).

## Release boundary

The v6 artifacts passed the full registered command surface on both main WPP and main WPS in three independent fresh deployments. Each deployment passed all three Kaspersky gates, ran for 720 seconds of callback monitoring with at least six callbacks per host, completed the WPP/WPS matrices, and left no target scratch or redirected job files. The repeated release gate is complete.

## Repeated deployment gate

| Run | Window | Qscan processed/detected/errors | Callbacks WPP/WPS | WPP/WPS surface | F0 | disks | transfer | Verdict |
|---|---|---:|---:|---:|---:|---:|---:|---|
| `release-run-2b` | 18:37:29 - 18:49:45 | 3548 / 0 / 0 | 65 / 65 | 17/17 | 10/10 | 2/2 | pass | PASS |
| `release-run-3` | 19:03:30 - 19:16:37 | 3572 / 0 / 0 | 60 / 64 | 17/17 | 10/10 | 2/2 | pass | PASS |
| `release-run-4` | 19:26:09 - 19:38:43 | 3572 / 0 / 0 | 65 / 65 | 17/17 | 10/10 | 2/2 | pass | PASS |

Per-run reports and raw evidence:

- [run-2b RESULT](release-run-2b/RESULT.md), [run-2b deploy log](release-run-2b/deploy-scan.log), [run-2b callback monitor](release-run-2b/callback-monitor.json)
- [run-3 RESULT](release-run-3/RESULT.md), [run-3 deploy log](release-run-3/deploy-scan.log), [run-3 callback monitor](release-run-3/callback-monitor.json)
- [run-4 RESULT](release-run-4/RESULT.md), [run-4 deploy log](release-run-4/deploy-scan.log), [run-4 callback monitor](release-run-4/callback-monitor.json)

The first `release-run-1` and first `release-run-2` attempt are preserved as failed diagnostic runs and are excluded from the three successful deployments. C++ x64/x86 compilation, Go agent tests, Python protocol/test harness compilation, deployment gates, and live matrices were executed. The root-module default vet diagnostics are retained in `build-logs/go-test-AdaptixServer-1.25.4.log` and are outside the direct HTTPS agent change set.

## Reproduction

最新源码和 release 包的独立留存清单：

- preserved-latest-20260721/PRESERVATION-MANIFEST.md
- preserved-latest-20260721/PRESERVED-SHA256SUMS
- preserved-latest-20260721/source/AdaptixC2-release-wpp-functional-v1.tar.gz

自研特色技术与官方 beacon_agent 对比：

- INNOVATIONS-VS-ORIGINAL-ADAPTIX.md
- [从代码到构建、部署和回连的完整流程](LOCAL_CANDIDATE_ROOT/END-TO-END-FLOW-BEGINNER.md)

```bash
cd LOCAL_ADAPTIXC2_ROOT
git show 72e54efee51ee70445344a81c4580142a505b0e2
DEPLOY_TAG=wpp-wps-f0-ps-encoding-20260721-165405 \
  bash LOCAL_CANDIDATE_ROOT/scan-and-deploy.sh
```

The full build commands and environment metadata are preserved in the candidate build logs and `profile_dll/build-meta.json`.

The assembled release package is [release-wpp-functional-v1/MANIFEST.md](release-wpp-functional-v1/MANIFEST.md); its file list is covered by `release-wpp-functional-v1/SHA256SUMS`.
