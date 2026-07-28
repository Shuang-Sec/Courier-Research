#!/usr/bin/env bash
set -euo pipefail

# 一键构建 WPP/WPS 侧 direct_https profile DLL。
#
# 本脚本负责：
# 1. 编译 Teamserver 侧 agent_direct_https.so 和 Windows Agent 对象；
# 2. 从现有 listener 读取 profile，链接 direct_https_profile.x64.dll；
# 3. 保存构建日志、元数据和 SHA-256。
#
# 本脚本只读取现有 listener，不创建 listener，不重启 Teamserver，
# 也不执行 Windows 靶机投放。cache.dat 打包和靶机部署由后续步骤负责。

ROOT="${ROOT:-/home/chenshuang/CTF/AdaptixC2}"
LISTENER="${LISTENER:-cdn_wpp_wps_v1_20260724_8448}"
SLEEP_VALUE="${SLEEP_VALUE:-10s}"
JITTER="${JITTER:-0}"
BEAT_DIALECT="${BEAT_DIALECT:-2}"
DIRECT_HTTPS_JOBS="${DIRECT_HTTPS_JOBS:-1}"
API_ENV="${API_ENV:-/home/chenshuang/CTF/.adaptix_api.env}"
CANDIDATE_ROOT="${CANDIDATE_ROOT:-/home/chenshuang/CTF/reports/cdn/wpp-wps-cdn-v1-20260724-111809}"
OUT_DIR="${OUT_DIR:-$CANDIDATE_ROOT/video-build-$(date +%Y%m%d-%H%M%S)}"

usage() {
    cat <<'USAGE'
用法：
  build-wpp-agent-dll.sh [选项]

选项：
  --listener NAME       使用现有 listener，默认 cdn_wpp_wps_v1_20260724_8448
  --out-dir DIR         输出目录，默认当前候选目录下的 video-build-时间戳
  --sleep VALUE         Agent sleep，默认 10s
  --jitter N            Agent jitter，默认 0
  --beat-dialect N      心跳协议方言，默认 2
  --api-env FILE        Adaptix API 环境文件
  -h, --help            显示帮助
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --listener) [[ $# -ge 2 ]] || { echo "缺少 --listener 参数" >&2; exit 2; }; LISTENER="$2"; shift 2 ;;
        --out-dir) [[ $# -ge 2 ]] || { echo "缺少 --out-dir 参数" >&2; exit 2; }; OUT_DIR="$2"; shift 2 ;;
        --sleep) [[ $# -ge 2 ]] || { echo "缺少 --sleep 参数" >&2; exit 2; }; SLEEP_VALUE="$2"; shift 2 ;;
        --jitter) [[ $# -ge 2 ]] || { echo "缺少 --jitter 参数" >&2; exit 2; }; JITTER="$2"; shift 2 ;;
        --beat-dialect) [[ $# -ge 2 ]] || { echo "缺少 --beat-dialect 参数" >&2; exit 2; }; BEAT_DIALECT="$2"; shift 2 ;;
        --api-env) [[ $# -ge 2 ]] || { echo "缺少 --api-env 参数" >&2; exit 2; }; API_ENV="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数：$1" >&2; usage >&2; exit 2 ;;
    esac
done

SRC="$ROOT/AdaptixServer/extenders/direct_https_agent"
PROFILE_BUILDER="$ROOT/research/memory-loader-lab/build_direct_https_profile_dll.py"

[[ -d "$ROOT" ]] || { echo "AdaptixC2 目录不存在：$ROOT" >&2; exit 1; }
[[ -d "$SRC" ]] || { echo "direct_https_agent 源码目录不存在：$SRC" >&2; exit 1; }
[[ -f "$PROFILE_BUILDER" ]] || { echo "profile 构建脚本不存在：$PROFILE_BUILDER" >&2; exit 1; }
[[ -f "$API_ENV" ]] || { echo "API 环境文件不存在：$API_ENV" >&2; exit 1; }

case "$BEAT_DIALECT" in
    0|1|2) ;;
    *) echo "--beat-dialect 只能是 0、1 或 2" >&2; exit 2 ;;
esac

case "$DIRECT_HTTPS_JOBS" in
    ''|*[!0-9]*) echo "DIRECT_HTTPS_JOBS 必须是正整数" >&2; exit 2 ;;
    0) echo "DIRECT_HTTPS_JOBS 必须大于 0" >&2; exit 2 ;;
esac

available_kb="$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)"
client_pid="$(pgrep -x AdaptixClient | head -n1 || true)"
if [[ -n "$client_pid" ]]; then
    client_rss_kb="$(ps -o rss= -p "$client_pid" | tr -d ' ' || true)"
    if [[ "$client_rss_kb" =~ ^[0-9]+$ && "$client_rss_kb" -gt $((8 * 1024 * 1024)) ]]; then
        client_rss_gib="$(awk -v kb="$client_rss_kb" 'BEGIN {printf "%.1f", kb / 1024 / 1024}')"
        echo "构建已停止：AdaptixClient 当前 RSS 约 ${client_rss_gib} GiB，请先关闭或重启客户端再执行构建。" >&2
        exit 3
    fi
fi
if [[ -z "$available_kb" || "$available_kb" -lt $((4 * 1024 * 1024)) ]]; then
    echo "构建已停止：当前可用内存低于 4 GiB，请先关闭高占用程序后再试。" >&2
    exit 3
fi

export PATH="/home/chenshuang/CTF/tools/go/bin:/home/chenshuang/CTF/tools/mingw/usr/bin:$PATH"
export GOCACHE="${GOCACHE:-/home/chenshuang/CTF/tools/gocache}"
export GOPATH="${GOPATH:-/home/chenshuang/CTF/tools/gopath}"
export GOPROXY="${GOPROXY:-off}"
export DIRECT_HTTPS_JOBS

mkdir -p "$OUT_DIR"
PROFILE_DIR="$OUT_DIR/profile_dll"
mkdir -p "$PROFILE_DIR"
BUILD_LOG="$OUT_DIR/build.log"

{
    echo "BUILD_TIME=$(date --iso-8601=seconds)"
    echo "ROOT=$ROOT"
    echo "LISTENER=$LISTENER"
    echo "SLEEP=$SLEEP_VALUE"
    echo "JITTER=$JITTER"
    echo "BEAT_DIALECT=$BEAT_DIALECT"
    echo "DIRECT_HTTPS_JOBS=$DIRECT_HTTPS_JOBS"
    echo "OUT_DIR=$OUT_DIR"
    echo "GOCACHE=$GOCACHE"
    echo "GOPATH=$GOPATH"
    echo "GOPROXY=$GOPROXY"
    git -C "$ROOT" rev-parse HEAD 2>/dev/null || true
    git -C "$ROOT" status --short --branch 2>/dev/null || true
} | tee "$OUT_DIR/build-config.txt"

echo "[1/3] 编译 direct_https_agent 插件和 Windows Agent 对象"
{
    cd "$SRC"
    export DIRECT_HTTPS_LAZY_HTTP_SEND=1
    export DIRECT_HTTPS_LAZY_WININET_INIT=1
    export DIRECT_HTTPS_LITE_CONNECTOR=1
    export DIRECT_HTTPS_NO_API_HASHING=1
    export DIRECT_HTTPS_BEAT_DIALECT="$BEAT_DIALECT"
    make clean
    make DIRECT_HTTPS_BEAT_DIALECT="$BEAT_DIALECT" DIRECT_HTTPS_JOBS="$DIRECT_HTTPS_JOBS"
} 2>&1 | tee -a "$BUILD_LOG"

cp "$SRC/dist/agent_direct_https.so" "$OUT_DIR/agent_direct_https.so"

echo "[2/3] 从现有 listener 生成 Windows x64 profile DLL"
python3 "$PROFILE_BUILDER" \
    --listener "$LISTENER" \
    --sleep "$SLEEP_VALUE" \
    --jitter "$JITTER" \
    --beat-dialect "$BEAT_DIALECT" \
    --lazy-wininet-init \
    --lite-connector \
    --env-file "$API_ENV" \
    --out-dir "$PROFILE_DIR" 2>&1 | tee -a "$BUILD_LOG"

cp "$PROFILE_DIR/direct_https_profile.x64.dll" "$OUT_DIR/direct_https_profile.x64.dll"

echo "[3/3] 保存构建摘要和哈希"
{
    echo "listener=$LISTENER"
    echo "profile_dll=$OUT_DIR/direct_https_profile.x64.dll"
    echo "server_plugin=$OUT_DIR/agent_direct_https.so"
    echo
    sha256sum \
        "$OUT_DIR/direct_https_profile.x64.dll" \
        "$OUT_DIR/agent_direct_https.so"
} | tee "$OUT_DIR/SHA256SUMS"

cat > "$OUT_DIR/BUILD-RESULT.txt" <<EOF
BUILD_STATUS=PASS
LISTENER=$LISTENER
PROFILE_DLL=$OUT_DIR/direct_https_profile.x64.dll
SERVER_PLUGIN=$OUT_DIR/agent_direct_https.so
PROFILE_DIR=$PROFILE_DIR
BUILD_LOG=$BUILD_LOG
SHA256SUMS=$OUT_DIR/SHA256SUMS
EOF

echo
echo "构建完成："
echo "  DLL:    $OUT_DIR/direct_https_profile.x64.dll"
echo "  plugin: $OUT_DIR/agent_direct_https.so"
echo "  记录:   $OUT_DIR/BUILD-RESULT.txt"
