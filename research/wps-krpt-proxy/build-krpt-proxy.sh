#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$ROOT/out-krpt}"
REPO_ROOT="${REPO_ROOT:-$(cd "$ROOT/../.." && pwd)}"
REAL_DLL="${REAL_DLL:?set REAL_DLL to the preserved original krpt_orig.dll path}"
CACHE_DAT="${CACHE_DAT:-$REPO_ROOT/research/memory-loader-lab/build/x64/cache.dat}"
ML_ROOT="${ML_ROOT:-$REPO_ROOT/research/memory-loader-lab}"
CC="x86_64-w64-mingw32-gcc"
PYTHON="${PYTHON:-python3}"
CFLAGS=(-O1 -Wall -Wextra -Werror)
DLLFLAGS=(-static -shared -s)
SILENT="${SILENT:-0}"
case "$SILENT" in
  0|1) ;;
  *) echo "SILENT must be 0 or 1" >&2; exit 2 ;;
esac
LOADER_DEFS=(
  -Dmain=dhpl_loader_main
  -DPROFILE_ONLY_RELEASE
  -DPROFILE_ONLY_NO_ENV_KEY
  -DPROFILE_ONLY_DYNAMIC_BCRYPT
  -DPROFILE_ONLY_DYNAMIC_MEM_API
  -DPROFILE_ONLY_DISABLE_MINGW_RUNTIME_PSEUDO_RELOC
)
PROXY_DEFS=()
if [[ "$SILENT" == 1 ]]; then
  PROXY_DEFS+=( -DPROFILE_ONLY_SILENT )
else
  LOADER_DEFS+=( -DPROFILE_ONLY_DIAG )
fi

mkdir -p "$OUT"

"$PYTHON" "$ROOT/gen_krpt_def.py" "$REAL_DLL" "$OUT/krpt_proxy.def"
cp -f "$REAL_DLL" "$OUT/krpt_orig.dll"
cp -f "$CACHE_DAT" "$OUT/cache.dat"

"$CC" "${CFLAGS[@]}" "${LOADER_DEFS[@]}" \
  -c "$ML_ROOT/src/loader_profile_only.c" \
  -o "$OUT/dhpl_loader_profile_only.x64.o"

"$CC" "${CFLAGS[@]}" "${PROXY_DEFS[@]}" "${DLLFLAGS[@]}" \
  "$ROOT/krpt_proxy_agent.c" \
  "$OUT/dhpl_loader_profile_only.x64.o" \
  "$OUT/krpt_proxy.def" \
  -o "$OUT/krpt.dll"

# Remove the alias left by older candidates so the output directory has one
# unambiguous WPS entry DLL.
rm -f "$OUT/krpt.agent.dll"

sha256sum \
  "$OUT/krpt_proxy.def" \
  "$OUT/dhpl_loader_profile_only.x64.o" \
  "$OUT/krpt.dll" \
  "$OUT/krpt_orig.dll" \
  "$OUT/cache.dat"
