#!/usr/bin/env python3
"""Pack the current direct_https DLL into a DHPL1 profile-only container.

DHPL1 = Direct HTTPS Profile Loader v1.

这个脚本是给当前 direct_https 学习版 payload 专门写的“离线预解析器”：

1. 在 Linux 构建阶段读取 direct_https_profile.x64.dll；
2. 离线解析 PE 头、section、relocation、import、TLS、exception table、export；
3. 把 loader 运行时真正需要的信息写成自定义 DHPL1 容器；
4. 不把 DOS header / NT header / section header table 原样塞进容器；
5. 预先找到 RunAgentDll 的 RVA，运行时 loader 不再需要 export table。

注意：这不是通用 PE packer。它只支持本实验里的 x64 direct_https DLL。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_KEY = "CHANGE_ME_MEMORY_LOADER_KEY"

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_TLS = 9

IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20

IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_DIR64 = 10

DHPL_MAGIC = b"DHPL1\x00\x00\x00"
DHPL_VERSION = 1

# 外层加密信封。内层明文仍是 DHPL1；磁盘文件从本轮开始是：
#   DHPLE2 header + salt + nonce + tag + AES-256-GCM ciphertext
#
# 说明：
# - v0 用 XOR，只能算“混淆”，没有真正的完整性校验；
# - v1 使用 AES-256-GCM + SHA256(passphrase) key；
# - v2 使用 AES-256-GCM + PBKDF2-HMAC-SHA256(passphrase, salt, iterations) key；
# - v2 比 v1 多了随机 salt 和迭代次数，避免同一 passphrase 每次派生出同一个 key。
ENC_MAGIC_V1 = b"DHPLE1\x00\x00"
ENC_MAGIC = b"DHPLE2\x00\x00"
ENC_VERSION = 2
ENC_ALG_AES256_GCM_SHA256_KEY = 1
ENC_ALG_AES256_GCM_PBKDF2_SHA256_KEY = 2
ENC_KDF_PBKDF2_HMAC_SHA256 = 1
ENC_PBKDF2_ITERATIONS = 100_000
ENC_AAD_V1 = b"DHPL1-AES256-GCM-SHA256KEY-v1"
ENC_AAD = b"DHPL1-AES256-GCM-PBKDF2-SHA256-v2"
ENC_HEADER_STRUCT_V1 = struct.Struct("<8sIIIIII")
ENC_HEADER_STRUCT = struct.Struct("<8sIIIIIIIII")

HEADER_STRUCT = struct.Struct("<8sIIIIQ" + "I" * 18)
SECTION_STRUCT = struct.Struct("<IIIIIIII")
IMPORT_FIXED_STRUCT = struct.Struct("<IHH")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_aes_key_sha256(passphrase: str) -> bytes:
    """Derive the legacy DHPLE1 AES-256 key used by older containers.

    这里选 SHA-256(passphrase) 是为了让 Windows 侧可以只依赖系统自带 CNG
    API 复现同一结果，不再引入额外第三方 crypto 代码。
    """

    raw = passphrase.encode("utf-8")
    if not raw:
        raise ValueError("empty key is not allowed")
    return hashlib.sha256(raw).digest()


def derive_aes_key_pbkdf2(passphrase: str, salt: bytes, iterations: int) -> bytes:
    """Derive the DHPLE2 AES-256 key with PBKDF2-HMAC-SHA256.

    相比 SHA256(passphrase)，PBKDF2 多了随机 salt 和迭代次数：
    - salt 让同一个 passphrase 每次生成不同 key；
    - iterations 提高暴力猜测 passphrase 的成本；
    - Windows loader 侧用 BCryptDeriveKeyPBKDF2 复现同一结果。
    """

    raw = passphrase.encode("utf-8")
    if not raw:
        raise ValueError("empty key is not allowed")
    if not salt:
        raise ValueError("empty salt is not allowed")
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    return hashlib.pbkdf2_hmac("sha256", raw, salt, iterations, dklen=32)


def encrypt_envelope_aes_gcm(plain: bytes, passphrase: str) -> tuple[bytes, dict]:
    """Encrypt DHPL1 plaintext with DHPLE2 AES-256-GCM + PBKDF2.

    Python 侧使用 cryptography；Windows loader 侧使用系统 bcrypt/CNG。
    输出格式是固定外层信封，loader 先解析 DHPLE2，再解密得到内层 DHPL1。
    """

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception as exc:  # pragma: no cover - 环境缺依赖时给清晰错误。
        raise RuntimeError("Python package 'cryptography' is required for AES-256-GCM packing") from exc

    salt = os.urandom(16)
    nonce = os.urandom(12)
    aes = AESGCM(derive_aes_key_pbkdf2(passphrase, salt, ENC_PBKDF2_ITERATIONS))
    ciphertext_and_tag = aes.encrypt(nonce, plain, ENC_AAD)
    ciphertext = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]
    header = ENC_HEADER_STRUCT.pack(
        ENC_MAGIC,
        ENC_VERSION,
        ENC_ALG_AES256_GCM_PBKDF2_SHA256_KEY,
        ENC_KDF_PBKDF2_HMAC_SHA256,
        ENC_PBKDF2_ITERATIONS,
        len(salt),
        len(nonce),
        len(tag),
        len(plain),
        len(ciphertext),
    )
    encrypted = header + salt + nonce + tag + ciphertext
    enc_meta = {
        "envelope": "DHPLE2",
        "algorithm": "AES-256-GCM",
        "key_derivation": "PBKDF2-HMAC-SHA256(passphrase, salt, iterations)",
        "aad": ENC_AAD.decode("ascii"),
        "salt_hex": salt.hex(),
        "iterations": ENC_PBKDF2_ITERATIONS,
        "nonce_hex": nonce.hex(),
        "tag_hex": tag.hex(),
        "ciphertext_size": len(ciphertext),
        "envelope_header_size": ENC_HEADER_STRUCT.size,
    }
    return encrypted, enc_meta


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def align_up(value: int, align: int) -> int:
    return (value + align - 1) & ~(align - 1)


def c_string(data: bytes, off: int, limit: int = 4096) -> str:
    if off < 0 or off >= len(data):
        raise ValueError(f"cstring offset out of file: 0x{off:x}")
    end = off
    hard = min(len(data), off + limit)
    while end < hard and data[end] != 0:
        end += 1
    if end >= hard:
        raise ValueError(f"unterminated cstring at 0x{off:x}")
    return data[off:end].decode("ascii")


def protection_from_characteristics(chars: int) -> int:
    """Convert PE section characteristics to final Win32 memory protection.

    v1 的目标是避免长期 RWX。因此如果某个 section 同时标记 execute+write，
    这里保守降为 PAGE_EXECUTE_READ。当前 direct_https DLL 正常不需要可写代码段。
    """

    executable = bool(chars & IMAGE_SCN_MEM_EXECUTE)
    readable = bool(chars & IMAGE_SCN_MEM_READ)
    writable = bool(chars & IMAGE_SCN_MEM_WRITE)
    if executable:
        if readable or writable:
            return PAGE_EXECUTE_READ
        return PAGE_EXECUTE
    if writable:
        return PAGE_READWRITE
    if readable:
        return PAGE_READONLY
    return PAGE_READONLY


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_ptr: int
    characteristics: int

    @property
    def mapped_size(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclass
class ImportRecord:
    module: str
    name: str
    iat_rva: int


class PEImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        self.sections: list[Section] = []
        self.data_directories: list[tuple[int, int]] = []
        self._parse_headers()

    def _parse_headers(self) -> None:
        d = self.data
        if len(d) < 0x100 or d[:2] != b"MZ":
            raise ValueError("input is not an MZ file")
        self.e_lfanew = u32(d, 0x3C)
        if self.e_lfanew <= 0 or self.e_lfanew + 0x18 >= len(d):
            raise ValueError("invalid e_lfanew")
        if d[self.e_lfanew : self.e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("missing PE signature")

        file_header = self.e_lfanew + 4
        self.machine = u16(d, file_header)
        self.number_of_sections = u16(d, file_header + 2)
        self.size_of_optional_header = u16(d, file_header + 16)
        if self.machine != IMAGE_FILE_MACHINE_AMD64:
            raise ValueError(f"only x64 PE is supported, machine=0x{self.machine:x}")

        opt = file_header + 20
        if opt + self.size_of_optional_header > len(d):
            raise ValueError("optional header exceeds file")
        self.optional_magic = u16(d, opt)
        if self.optional_magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            raise ValueError(f"only PE32+ is supported, optional_magic=0x{self.optional_magic:x}")

        self.entry_point_rva = u32(d, opt + 0x10)
        self.image_base = u64(d, opt + 0x18)
        self.section_alignment = u32(d, opt + 0x20)
        self.file_alignment = u32(d, opt + 0x24)
        self.size_of_image = u32(d, opt + 0x38)
        self.size_of_headers = u32(d, opt + 0x3C)
        self.number_of_rva_and_sizes = u32(d, opt + 0x6C)

        dir_off = opt + 0x70
        max_dirs = min(self.number_of_rva_and_sizes, 16)
        for i in range(max_dirs):
            self.data_directories.append((u32(d, dir_off + i * 8), u32(d, dir_off + i * 8 + 4)))
        while len(self.data_directories) < 16:
            self.data_directories.append((0, 0))

        sec_off = opt + self.size_of_optional_header
        for i in range(self.number_of_sections):
            off = sec_off + i * 40
            if off + 40 > len(d):
                raise ValueError("section table exceeds file")
            raw_name = d[off : off + 8].split(b"\x00", 1)[0]
            name = raw_name.decode("ascii", "replace")
            self.sections.append(
                Section(
                    name=name,
                    virtual_size=u32(d, off + 8),
                    virtual_address=u32(d, off + 12),
                    raw_size=u32(d, off + 16),
                    raw_ptr=u32(d, off + 20),
                    characteristics=u32(d, off + 36),
                )
            )

    def directory(self, index: int) -> tuple[int, int]:
        return self.data_directories[index]

    def rva_to_offset(self, rva: int, size: int = 1) -> int:
        if rva < self.size_of_headers:
            if rva + size <= len(self.data):
                return rva
        for s in self.sections:
            start = s.virtual_address
            end = start + max(s.virtual_size, s.raw_size)
            if start <= rva < end:
                delta = rva - start
                if delta + size > s.raw_size:
                    raise ValueError(f"RVA 0x{rva:x}+0x{size:x} points past raw data of section {s.name}")
                off = s.raw_ptr + delta
                if off + size > len(self.data):
                    raise ValueError(f"RVA 0x{rva:x}+0x{size:x} points past file")
                return off
        raise ValueError(f"cannot translate RVA 0x{rva:x}")

    def read_at_rva(self, rva: int, size: int) -> bytes:
        return self.data[self.rva_to_offset(rva, size) : self.rva_to_offset(rva, size) + size]

    def parse_run_agent_rva(self) -> int:
        export_rva, export_size = self.directory(IMAGE_DIRECTORY_ENTRY_EXPORT)
        if not export_rva or export_size < 40:
            raise ValueError("DLL has no export directory")
        off = self.rva_to_offset(export_rva, 40)
        (
            _characteristics,
            _time_date_stamp,
            _major,
            _minor,
            _name,
            ordinal_base,
            number_of_functions,
            number_of_names,
            address_of_functions,
            address_of_names,
            address_of_name_ordinals,
        ) = struct.unpack_from("<IIHHIIIIIII", self.data, off)

        for i in range(number_of_names):
            name_rva = u32(self.data, self.rva_to_offset(address_of_names + i * 4, 4))
            name = c_string(self.data, self.rva_to_offset(name_rva))
            if name != "RunAgentDll":
                continue
            ordinal_index = u16(self.data, self.rva_to_offset(address_of_name_ordinals + i * 2, 2))
            if ordinal_index >= number_of_functions:
                raise ValueError("RunAgentDll ordinal index out of range")
            func_rva = u32(self.data, self.rva_to_offset(address_of_functions + ordinal_index * 4, 4))
            if export_rva <= func_rva < export_rva + export_size:
                raise ValueError("forwarded RunAgentDll export is not supported")
            return func_rva
        raise ValueError("cannot find exported RunAgentDll")

    def parse_relocations(self) -> list[int]:
        reloc_rva, reloc_size = self.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        if not reloc_rva or not reloc_size:
            return []
        relocs: list[int] = []
        cursor = self.rva_to_offset(reloc_rva, reloc_size)
        end = cursor + reloc_size
        while cursor + 8 <= end:
            page_rva, block_size = struct.unpack_from("<II", self.data, cursor)
            if page_rva == 0 and block_size == 0:
                break
            if block_size < 8 or cursor + block_size > end:
                raise ValueError("invalid relocation block")
            count = (block_size - 8) // 2
            entry_off = cursor + 8
            for i in range(count):
                entry = u16(self.data, entry_off + i * 2)
                typ = entry >> 12
                off = entry & 0x0FFF
                if typ == IMAGE_REL_BASED_ABSOLUTE:
                    continue
                if typ != IMAGE_REL_BASED_DIR64:
                    raise ValueError(f"unsupported relocation type {typ} at page RVA 0x{page_rva:x}")
                relocs.append(page_rva + off)
            cursor += block_size
        return sorted(set(relocs))

    def parse_imports(self) -> list[ImportRecord]:
        import_rva, import_size = self.directory(IMAGE_DIRECTORY_ENTRY_IMPORT)
        if not import_rva or not import_size:
            return []
        imports: list[ImportRecord] = []
        desc = self.rva_to_offset(import_rva, 20)
        while True:
            original_first_thunk, _time, _forwarder, name_rva, first_thunk = struct.unpack_from("<IIIII", self.data, desc)
            if not any((original_first_thunk, name_rva, first_thunk)):
                break
            module = c_string(self.data, self.rva_to_offset(name_rva))
            thunk_rva = original_first_thunk or first_thunk
            index = 0
            while True:
                thunk_value = u64(self.data, self.rva_to_offset(thunk_rva + index * 8, 8))
                if thunk_value == 0:
                    break
                if thunk_value & IMAGE_ORDINAL_FLAG64:
                    raise ValueError(f"ordinal import in {module} is not supported")
                hint_name_rva = thunk_value & 0x7FFFFFFFFFFFFFFF
                name = c_string(self.data, self.rva_to_offset(hint_name_rva + 2))
                imports.append(ImportRecord(module=module, name=name, iat_rva=first_thunk + index * 8))
                index += 1
            desc += 20
        return imports

    def parse_tls_callbacks(self) -> list[int]:
        tls_rva, tls_size = self.directory(IMAGE_DIRECTORY_ENTRY_TLS)
        if not tls_rva or tls_size < 40:
            return []
        off = self.rva_to_offset(tls_rva, 40)
        (
            _start_raw,
            _end_raw,
            _address_of_index,
            address_of_callbacks,
            _size_of_zero_fill,
            _characteristics,
        ) = struct.unpack_from("<QQQQII", self.data, off)
        if not address_of_callbacks:
            return []
        callback_array_rva = address_of_callbacks - self.image_base
        callbacks: list[int] = []
        cur = self.rva_to_offset(callback_array_rva, 8)
        while True:
            callback_va = u64(self.data, cur)
            if callback_va == 0:
                break
            if callback_va < self.image_base or callback_va >= self.image_base + self.size_of_image:
                raise ValueError(f"TLS callback VA out of image: 0x{callback_va:x}")
            callbacks.append(callback_va - self.image_base)
            cur += 8
        return callbacks


def build_plain_container(pe: PEImage) -> tuple[bytes, dict]:
    run_agent_rva = pe.parse_run_agent_rva()
    relocs = pe.parse_relocations()
    imports = pe.parse_imports()
    tls_callbacks = pe.parse_tls_callbacks()
    exception_rva, exception_size = pe.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION)

    active_sections = [
        s
        for s in pe.sections
        if s.virtual_address and (s.virtual_size or s.raw_size)
    ]

    section_records_len = len(active_sections) * SECTION_STRUCT.size
    reloc_records_len = len(relocs) * 4
    tls_records_len = len(tls_callbacks) * 4

    import_records = bytearray()
    for item in imports:
        mod = item.module.encode("ascii")
        name = item.name.encode("ascii")
        if len(mod) > 0xFFFF or len(name) > 0xFFFF:
            raise ValueError("import string too long")
        import_records += IMPORT_FIXED_STRUCT.pack(item.iat_rva, len(mod), len(name))
        import_records += mod + name
        while len(import_records) % 4:
            import_records.append(0)

    sections_offset = HEADER_STRUCT.size
    relocs_offset = sections_offset + section_records_len
    imports_offset = relocs_offset + reloc_records_len
    tls_offset = imports_offset + len(import_records)
    data_offset = align_up(tls_offset + tls_records_len, 16)

    section_data = bytearray()
    section_records = bytearray()
    section_meta = []
    for s in active_sections:
        data_size = 0
        data_blob = b""
        if s.raw_size and not (s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA):
            if s.raw_ptr + s.raw_size > len(pe.data):
                raise ValueError(f"raw data for section {s.name} exceeds file")
            data_blob = pe.data[s.raw_ptr : s.raw_ptr + s.raw_size]
            data_size = len(data_blob)
        blob_offset = data_offset + len(section_data) if data_size else 0
        section_records += SECTION_STRUCT.pack(
            s.virtual_address,
            s.mapped_size,
            s.raw_size,
            blob_offset,
            data_size,
            s.characteristics,
            protection_from_characteristics(s.characteristics),
            0,
        )
        section_data += data_blob
        section_meta.append(
            {
                "name": s.name,
                "virtual_address": f"0x{s.virtual_address:x}",
                "virtual_size": s.virtual_size,
                "mapped_size": s.mapped_size,
                "raw_size": s.raw_size,
                "data_size": data_size,
                "characteristics": f"0x{s.characteristics:08x}",
                "protection": f"0x{protection_from_characteristics(s.characteristics):x}",
            }
        )

    relocs_blob = b"".join(struct.pack("<I", rva) for rva in relocs)
    tls_blob = b"".join(struct.pack("<I", rva) for rva in tls_callbacks)
    pad = b"\x00" * (data_offset - (tls_offset + tls_records_len))
    total_size = data_offset + len(section_data)

    header = HEADER_STRUCT.pack(
        DHPL_MAGIC,
        DHPL_VERSION,
        IMAGE_FILE_MACHINE_AMD64,
        HEADER_STRUCT.size,
        0,
        pe.image_base,
        pe.size_of_image,
        pe.size_of_headers,
        pe.entry_point_rva,
        run_agent_rva,
        len(active_sections),
        len(relocs),
        len(imports),
        len(tls_callbacks),
        exception_rva,
        exception_size,
        sections_offset,
        relocs_offset,
        imports_offset,
        tls_offset,
        data_offset,
        total_size,
        0,
        0,
    )

    plain = header + bytes(section_records) + relocs_blob + bytes(import_records) + tls_blob + pad + bytes(section_data)
    if len(plain) != total_size:
        raise AssertionError(f"DHPL size mismatch: len={len(plain)} total={total_size}")

    meta = {
        "format": "DHPL1",
        "input": str(pe.path),
        "input_sha256": sha256_file(pe.path),
        "preferred_image_base": f"0x{pe.image_base:x}",
        "image_size": pe.size_of_image,
        "size_of_headers": pe.size_of_headers,
        "entry_point_rva": f"0x{pe.entry_point_rva:x}",
        "run_agent_rva": f"0x{run_agent_rva:x}",
        "section_count": len(active_sections),
        "reloc_count": len(relocs),
        "import_count": len(imports),
        "tls_callback_count": len(tls_callbacks),
        "exception_rva": f"0x{exception_rva:x}",
        "exception_size": exception_size,
        "plain_size": len(plain),
        "plain_sha256": sha256_bytes(plain),
        "plain_first16": plain[:16].hex(),
        "sections": section_meta,
        "imports": [
            {"module": item.module, "name": item.name, "iat_rva": f"0x{item.iat_rva:x}"}
            for item in imports
        ],
        "tls_callbacks": [f"0x{x:x}" for x in tls_callbacks],
        "reloc_sample": [f"0x{x:x}" for x in relocs[:32]],
    }
    return plain, meta


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pack direct_https_profile.x64.dll into encrypted DHPL1 container")
    parser.add_argument("input_dll", type=Path)
    parser.add_argument("output_dhpl", type=Path)
    parser.add_argument("key", nargs="?", default=DEFAULT_KEY)
    args = parser.parse_args(argv)

    pe = PEImage(args.input_dll)
    plain, meta = build_plain_container(pe)
    encrypted, enc_meta = encrypt_envelope_aes_gcm(plain, args.key)

    args.output_dhpl.parent.mkdir(parents=True, exist_ok=True)
    args.output_dhpl.write_bytes(encrypted)
    meta.update(
        {
            "output": str(args.output_dhpl),
            "output_sha256": sha256_file(args.output_dhpl),
            "output_size": args.output_dhpl.stat().st_size,
            "encryption": enc_meta,
            "encrypted_first16": encrypted[:16].hex(),
            "disk_starts_with_mz": encrypted.startswith(b"MZ"),
            "disk_starts_with_dhpl": encrypted.startswith(DHPL_MAGIC),
            "disk_starts_with_dhple": encrypted.startswith(ENC_MAGIC),
            "disk_starts_with_dhple1": encrypted.startswith(ENC_MAGIC_V1),
            "disk_starts_with_dhple2": encrypted.startswith(ENC_MAGIC),
            "decrypted_starts_with_mz": plain.startswith(b"MZ"),
            "decrypted_starts_with_dhpl": plain.startswith(DHPL_MAGIC),
        }
    )
    meta_path = args.output_dhpl.with_suffix(args.output_dhpl.suffix + ".meta.json")
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
