#!/usr/bin/env python3
"""
对 profile-only loader 的 release/diag 两个 PE 产物做静态差分。

这个脚本不依赖 pefile；只解析本实验需要的 PE64 元数据：
  - 基本 PE header / optional header
  - section 表与 section entropy
  - import table
  - ASCII / UTF-16LE 字符串集合

输出：
  - loader-static-diff.json     机器可读完整结果
  - loader-static-diff.md       给实验报告直接引用的 Markdown 摘要
  - release-strings-only.txt    release 独有字符串
  - diag-strings-only.txt       diag 独有字符串
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import hashlib
import json
import math
import re
import struct
from pathlib import Path
from typing import Any


IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_IAT = 12


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def read_cstr(data: bytes, off: int, limit: int = 4096) -> str:
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\x00", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("ascii", "replace")


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    pat = rb"[\x20-\x7e]{%d,}" % min_len
    return sorted(set(m.group(0).decode("ascii", "replace") for m in re.finditer(pat, data)))


def extract_utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: set[str] = set()
    cur: list[int] = []
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 0x20 <= lo <= 0x7E:
            cur.append(lo)
        else:
            if len(cur) >= min_len:
                out.add(bytes(cur).decode("ascii", "replace"))
            cur = []
        i += 2
    if len(cur) >= min_len:
        out.add(bytes(cur).decode("ascii", "replace"))
    return sorted(out)


@dataclasses.dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int
    entropy: float
    sha256: str

    @property
    def readable_characteristics(self) -> list[str]:
        flags = []
        if self.characteristics & 0x20000000:
            flags.append("EXECUTE")
        if self.characteristics & 0x40000000:
            flags.append("READ")
        if self.characteristics & 0x80000000:
            flags.append("WRITE")
        if self.characteristics & 0x20:
            flags.append("CODE")
        if self.characteristics & 0x40:
            flags.append("INIT_DATA")
        if self.characteristics & 0x80:
            flags.append("UNINIT_DATA")
        return flags


class PE:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.size = len(self.data)
        self.sha256 = sha256_bytes(self.data)
        self.file_entropy = entropy(self.data)
        self.sections: list[Section] = []
        self.data_directories: list[dict[str, int]] = []
        self.imports: dict[str, list[str]] = {}
        self.header: dict[str, Any] = {}
        self.ascii_strings = extract_ascii_strings(self.data)
        self.utf16_strings = extract_utf16le_strings(self.data)
        self._parse()

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            span = max(s.virtual_size, s.raw_size)
            if s.virtual_address <= rva < s.virtual_address + span:
                off = s.raw_ptr + (rva - s.virtual_address)
                if 0 <= off < len(self.data):
                    return off
        return None

    def _parse(self) -> None:
        if self.data[:2] != b"MZ":
            raise ValueError(f"{self.path} is not MZ")
        e_lfanew = self.u32(0x3C)
        if self.data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError(f"{self.path} has no PE signature")
        coff = e_lfanew + 4
        machine = self.u16(coff)
        number_of_sections = self.u16(coff + 2)
        timestamp = self.u32(coff + 4)
        size_of_optional_header = self.u16(coff + 16)
        characteristics = self.u16(coff + 18)
        opt = coff + 20
        magic = self.u16(opt)
        if magic != 0x20B:
            raise ValueError(f"{self.path} is not PE32+")
        address_of_entry_point = self.u32(opt + 16)
        image_base = self.u64(opt + 24)
        section_alignment = self.u32(opt + 32)
        file_alignment = self.u32(opt + 36)
        size_of_image = self.u32(opt + 56)
        size_of_headers = self.u32(opt + 60)
        subsystem = self.u16(opt + 68)
        dll_characteristics = self.u16(opt + 70)
        number_of_rva_and_sizes = self.u32(opt + 108)
        dd_off = opt + 112
        self.data_directories = []
        for i in range(min(number_of_rva_and_sizes, 16)):
            self.data_directories.append({"index": i, "rva": self.u32(dd_off + i * 8), "size": self.u32(dd_off + i * 8 + 4)})
        sec_off = opt + size_of_optional_header
        self.sections = []
        for i in range(number_of_sections):
            off = sec_off + i * 40
            name = self.data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
            virtual_size = self.u32(off + 8)
            virtual_address = self.u32(off + 12)
            raw_size = self.u32(off + 16)
            raw_ptr = self.u32(off + 20)
            characteristics_s = self.u32(off + 36)
            raw = self.data[raw_ptr : raw_ptr + raw_size] if raw_size else b""
            self.sections.append(
                Section(
                    name=name,
                    virtual_size=virtual_size,
                    virtual_address=virtual_address,
                    raw_size=raw_size,
                    raw_ptr=raw_ptr,
                    characteristics=characteristics_s,
                    entropy=entropy(raw),
                    sha256=sha256_bytes(raw),
                )
            )
        self.header = {
            "path": str(self.path),
            "size": self.size,
            "sha256": self.sha256,
            "entropy": self.file_entropy,
            "e_lfanew": e_lfanew,
            "machine": hex(machine),
            "number_of_sections": number_of_sections,
            "timestamp": timestamp,
            "characteristics": hex(characteristics),
            "optional_magic": hex(magic),
            "entry_point_rva": hex(address_of_entry_point),
            "image_base": hex(image_base),
            "section_alignment": hex(section_alignment),
            "file_alignment": hex(file_alignment),
            "size_of_image": hex(size_of_image),
            "size_of_headers": hex(size_of_headers),
            "subsystem": subsystem,
            "dll_characteristics": hex(dll_characteristics),
            "number_of_rva_and_sizes": number_of_rva_and_sizes,
        }
        self.imports = self._parse_imports()

    def _parse_imports(self) -> dict[str, list[str]]:
        if len(self.data_directories) <= IMAGE_DIRECTORY_ENTRY_IMPORT:
            return {}
        imp = self.data_directories[IMAGE_DIRECTORY_ENTRY_IMPORT]
        if not imp["rva"] or not imp["size"]:
            return {}
        off = self.rva_to_off(imp["rva"])
        if off is None:
            return {}
        imports: dict[str, list[str]] = {}
        idx = 0
        while off + idx * 20 + 20 <= len(self.data):
            d = off + idx * 20
            original_first_thunk = self.u32(d)
            name_rva = self.u32(d + 12)
            first_thunk = self.u32(d + 16)
            if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
                break
            name_off = self.rva_to_off(name_rva)
            mod = read_cstr(self.data, name_off) if name_off is not None else f"<bad_rva_{name_rva:x}>"
            thunk_rva = original_first_thunk or first_thunk
            thunk_off = self.rva_to_off(thunk_rva)
            funcs: list[str] = []
            if thunk_off is not None:
                j = 0
                while thunk_off + j * 8 + 8 <= len(self.data):
                    val = self.u64(thunk_off + j * 8)
                    if val == 0:
                        break
                    if val & (1 << 63):
                        funcs.append(f"ordinal:{val & 0xFFFF}")
                    else:
                        hint_name_off = self.rva_to_off(val)
                        funcs.append(read_cstr(self.data, hint_name_off + 2) if hint_name_off is not None else f"<bad_hint_{val:x}>")
                    j += 1
            imports[mod] = funcs
            idx += 1
        return imports

    def to_json(self) -> dict[str, Any]:
        return {
            "header": self.header,
            "sections": [
                {
                    **dataclasses.asdict(s),
                    "flags": s.readable_characteristics,
                }
                for s in self.sections
            ],
            "data_directories": self.data_directories,
            "imports": self.imports,
            "string_counts": {"ascii": len(self.ascii_strings), "utf16le": len(self.utf16_strings)},
        }


def compact_string_list(values: list[str], limit: int = 120) -> list[str]:
    cleaned = []
    for s in values:
        if len(s) > 180:
            s = s[:177] + "..."
        cleaned.append(s)
    return cleaned[:limit]


def keyword_hits(strings: list[str]) -> dict[str, list[str]]:
    keywords = [
        "DHPL",
        "DHPLE",
        "PROFILE",
        "KEY",
        "ERROR",
        "RunAgentDll",
        "VirtualAlloc",
        "VirtualProtect",
        "LoadLibrary",
        "GetProcAddress",
        "bcrypt",
        "BCrypt",
        "KERNEL32",
        "ADVAPI",
        "WININET",
        "status",
        "loader",
    ]
    out: dict[str, list[str]] = {}
    for k in keywords:
        vals = [s for s in strings if k.lower() in s.lower()]
        if vals:
            out[k] = compact_string_list(vals, 40)
    return out


def write_markdown(out: Path, release: PE, diag: PE, result: dict[str, Any], release_only: list[str], diag_only: list[str]) -> None:
    def section_table(pe: PE) -> str:
        lines = ["| name | raw | virt | flags | entropy | sha256[:12] |", "|---|---:|---:|---|---:|---|"]
        for s in pe.sections:
            lines.append(
                f"| `{s.name}` | {s.raw_size} | {s.virtual_size} | `{','.join(s.readable_characteristics)}` | {s.entropy:.3f} | `{s.sha256[:12]}` |"
            )
        return "\n".join(lines)

    def import_table(pe: PE) -> str:
        lines = ["| module | count | imports |", "|---|---:|---|"]
        for mod, funcs in sorted(pe.imports.items()):
            sample = ", ".join(funcs[:12])
            if len(funcs) > 12:
                sample += f", ... (+{len(funcs)-12})"
            lines.append(f"| `{mod}` | {len(funcs)} | `{sample}` |")
        return "\n".join(lines) if len(lines) > 2 else "_No imports parsed._"

    md = f"""# profile-only loader release/diag 静态差分

## 目标

比较 `loader_profile_only.x64.exe` 与 `loader_profile_only_diag.x64.exe`，解释为什么当前 Kaspersky 测试中 release 落地被处理、diag 反而能上线。

## 样本

| variant | path | size | sha256 | entropy |
|---|---|---:|---|---:|
| release | `{release.path}` | {release.size} | `{release.sha256}` | {release.file_entropy:.3f} |
| diag | `{diag.path}` | {diag.size} | `{diag.sha256}` | {diag.file_entropy:.3f} |

## 关键差异摘要

- 文件大小：diag 比 release 大 **{diag.size - release.size} bytes**。
- 字符串数量：release ASCII={len(release.ascii_strings)} UTF16={len(release.utf16_strings)}；diag ASCII={len(diag.ascii_strings)} UTF16={len(diag.utf16_strings)}。
- diag 独有字符串数量：{len(diag_only)}；release 独有字符串数量：{len(release_only)}。
- section 名称是否一致：{result['section_names_equal']}。
- import module 是否一致：{result['import_modules_equal']}。
- import function 是否一致：{result['import_functions_equal']}。

## release sections

{section_table(release)}

## diag sections

{section_table(diag)}

## release imports

{import_table(release)}

## diag imports

{import_table(diag)}

## diag 独有关键字符串命中

```text
{json.dumps(result['diag_keyword_hits'], ensure_ascii=False, indent=2)}
```

## release 独有关键字符串命中

```text
{json.dumps(result['release_keyword_hits'], ensure_ascii=False, indent=2)}
```

## 解释

当前静态差分显示：release 和 diag 的 section 名称一致，但导入表有一个很小的差异：diag 因为 `diag_log_num()` 使用 `wsprintfA`、`diag_log()` 写状态文件，所以多出 `USER32.dll!wsprintfA` 与 `KERNEL32.dll!WriteFile`。更大的差异来自编译宏导致的可见字符串、日志分支、代码布局和文件大小。diag 版携带大量 `DHPL_*` / `DHPLE*` 状态字符串与错误处理文本；release 版这些字符串被预处理移除，体积更小，代码形状更紧凑。

这解释了一个重要方向：Kaspersky 处理 release 不一定是因为“字符串更多”，反而可能是 release 优化后的代码布局/低噪声小体积样本触发了静态或信誉评分；diag 因为多了日志分支和状态文本，二进制形态发生变化，当前环境下没有命中同一规则。

## 下一步建议

1. 做 `release_plus_diag_strings`：保持 release 功能，但仅加入少量 benign 状态字符串，判断是否是字符串/布局扰动带来的差异。
2. 做 `release_no_strip`：取消 `-s`/strip，判断符号/节信息变化是否影响落地处理。
3. 做 `release_O0` / `release_O1`：改变优化等级，判断是否是 release 优化后的代码形状触发。
4. 每个变体仍使用 `ssh_b64` 传输，避免 HTTP 下载层污染结论。
"""
    out.write_text(md, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", required=True, type=Path)
    ap.add_argument("--diag", required=True, type=Path)
    ap.add_argument("--out-dir", required=True, type=Path)
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    release = PE(args.release)
    diag = PE(args.diag)

    rel_strings = set(release.ascii_strings + release.utf16_strings)
    diag_strings = set(diag.ascii_strings + diag.utf16_strings)
    release_only = sorted(rel_strings - diag_strings)
    diag_only = sorted(diag_strings - rel_strings)

    release_import_funcs = sorted({f"{m}!{fn}" for m, fs in release.imports.items() for fn in fs})
    diag_import_funcs = sorted({f"{m}!{fn}" for m, fs in diag.imports.items() for fn in fs})

    result = {
        "release": release.to_json(),
        "diag": diag.to_json(),
        "section_names_equal": [s.name for s in release.sections] == [s.name for s in diag.sections],
        "import_modules_equal": sorted(release.imports) == sorted(diag.imports),
        "import_functions_equal": release_import_funcs == diag_import_funcs,
        "release_only_string_count": len(release_only),
        "diag_only_string_count": len(diag_only),
        "release_keyword_hits": keyword_hits(release_only),
        "diag_keyword_hits": keyword_hits(diag_only),
        "release_only_imports": sorted(set(release_import_funcs) - set(diag_import_funcs)),
        "diag_only_imports": sorted(set(diag_import_funcs) - set(release_import_funcs)),
    }

    (args.out_dir / "loader-static-diff.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (args.out_dir / "release-strings-only.txt").write_text("\n".join(compact_string_list(release_only, 10000)) + "\n", encoding="utf-8")
    (args.out_dir / "diag-strings-only.txt").write_text("\n".join(compact_string_list(diag_only, 10000)) + "\n", encoding="utf-8")
    write_markdown(args.out_dir / "loader-static-diff.md", release, diag, result, release_only, diag_only)
    print(json.dumps({
        "out_dir": str(args.out_dir),
        "release_sha256": release.sha256,
        "diag_sha256": diag.sha256,
        "release_size": release.size,
        "diag_size": diag.size,
        "release_only_string_count": len(release_only),
        "diag_only_string_count": len(diag_only),
        "import_functions_equal": result["import_functions_equal"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
