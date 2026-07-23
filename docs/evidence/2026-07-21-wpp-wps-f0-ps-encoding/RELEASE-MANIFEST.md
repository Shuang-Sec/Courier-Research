# `release-wpp-functional-v1`

## Source

- Source commit: `72e54efee51ee70445344a81c4580142a505b0e2`
- Local source tag: `release-wpp-functional-v1`
- Listener: `HTTPS_LISTENER`
- Profile: x64, sleep `10s`, jitter `0`, beat dialect `2`, lite WinINet connector
- Functional scope: `hello`, `cmd`, `powershell`, `pwd`, `cd`, `ls`, `cat`, `mkdir`, `rm`, `cp`, `mv`, `disks`, `upload`, `download`

## Contents

- `cache.dat`: packaged profile/configuration
- `krpt.dll`, `krpt.agent.dll`: WPS proxy artifacts
- `agent_direct_https.so`: runtime plugin
- `profile_dll/direct_https_profile.x64.dll`: profile DLL
- `profile_dll/direct_https_profile.x64.bin`: profile XOR/container form
- `profile_dll/profile.bin`: profile payload
- `profile_dll/build-meta.json`: profile build metadata
- `build-logs/`: profile, packaging, proxy, x86, and Go 1.25.4 test logs
- `scan-and-deploy.sh`: reproducible deployment and Kaspersky gate wrapper
- `release-callback-monitor.py`: 720-second callback monitor
- `SHA256SUMS`: hash list for every package file

## Verified release gate

The same artifacts passed three independent fresh deployments:

| Run | Fresh Qscan | Callback monitor | WPP/WPS matrix | F0 | disks | Upload/download |
|---|---|---:|---:|---:|---:|---|
| `release-run-2b` | 3548 / 0 / 0 | 65 / 65 | 17/17 | 10/10 | 2/2 | pass |
| `release-run-3` | 3572 / 0 / 0 | 60 / 64 | 17/17 | 10/10 | 2/2 | pass |
| `release-run-4` | 3572 / 0 / 0 | 65 / 65 | 17/17 | 10/10 | 2/2 | pass |

The Qscan columns are `processed / detected / errors`. Each callback monitor ran for 720 seconds, and each WPP/WPS host exceeded the six-callback minimum. Static scans and `Scan_System_Memory` were also zero-detection, zero-error, RC 0 in every run.

## Reproduction reference

The complete evidence is under the parent candidate directory:

- `../release-run-2b/RESULT.md`
- `../release-run-3/RESULT.md`
- `../release-run-4/RESULT.md`
- `../RESULT.md`

Go `1.25.4` was run from an isolated toolchain. The direct HTTPS agent module passed `go test ./...`; the AdaptixServer root module passed `go test -vet=off ./...`, while default vet reports existing non-constant format-string diagnostics in `logs.*` calls. The raw outputs are included in `build-logs/`. C++ x64/x86 builds, Python test harness compilation, deployment, Kaspersky gates, and live WPP/WPS matrices were executed.
