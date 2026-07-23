#!/usr/bin/env python3
"""In-place replacement of selected release-only diagnostic byte strings.

This is intentionally small and conservative: it preserves file size and only
zeroes exact byte sequences provided on argv.  It is used for the production-ish
loader variant to remove a MinGW CRT pseudo-reloc diagnostic string that is not
part of the loader's normal execution path.
"""
from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="zero exact byte strings in a PE without changing file size")
    parser.add_argument("path", type=Path)
    parser.add_argument("strings", nargs="+")
    args = parser.parse_args()

    data = bytearray(args.path.read_bytes())
    changed = []
    for text in args.strings:
        needle = text.encode("utf-8")
        pos = data.find(needle)
        if pos < 0:
            changed.append({"string": text, "found": False, "offset": -1})
            continue
        while pos >= 0:
            data[pos : pos + len(needle)] = b"\x00" * len(needle)
            changed.append({"string": text, "found": True, "offset": pos})
            pos = data.find(needle, pos + len(needle))
    args.path.write_bytes(data)
    for row in changed:
        if row["found"]:
            print(f"scrubbed offset=0x{row['offset']:x} string={row['string']!r}")
        else:
            print(f"not-found string={row['string']!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
