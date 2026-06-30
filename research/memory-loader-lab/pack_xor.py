#!/usr/bin/env python3
"""XOR packer for the memory-loader learning lab.

Usage:
  python3 pack_xor.py input.dll output.bin key
"""
from __future__ import annotations
import hashlib
import pathlib
import sys


def xor(data: bytes, key: bytes) -> bytes:
    """用循环 key 对 data 做 XOR。

    XOR 的特点是：同样的 key 连续处理两次会还原原文。

    构建阶段：
        direct_https_profile.x64.dll --xor--> direct_https_profile.x64.bin

    运行阶段：
        cache.dat/direct_https_profile.x64.bin --xor--> 原始 DLL 字节

    这只是学习实验里的轻量封装，不等价于强加密。
    """
    if not key:
        raise ValueError("empty key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def main() -> int:
    # 参数固定为 input.dll、output.bin、key，方便构建脚本调用并记录 hash。
    if len(sys.argv) != 4:
        print("usage: pack_xor.py input.dll output.bin key", file=sys.stderr)
        return 2
    src = pathlib.Path(sys.argv[1])
    dst = pathlib.Path(sys.argv[2])
    key = sys.argv[3].encode("utf-8")
    data = src.read_bytes()
    enc = xor(data, key)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(enc)
    # 输出这些字段是为了让报告能精确记录样本和 payload hash。
    print(f"INPUT={src}")
    print(f"OUTPUT={dst}")
    print(f"INPUT_SIZE={len(data)}")
    print(f"OUTPUT_SIZE={len(enc)}")
    print(f"INPUT_SHA256={hashlib.sha256(data).hexdigest()}")
    print(f"OUTPUT_SHA256={hashlib.sha256(enc).hexdigest()}")
    print(f"KEY_LEN={len(key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
