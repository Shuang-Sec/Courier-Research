#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path


LINE_RE = re.compile(r'^\s*\[\s*\d+\]\s+\+base\[\s*(\d+)\]\s+[0-9A-Fa-f]+\s+(\S+)\s*$')


def parse_exports(dll_path: Path):
    out = subprocess.check_output(
        ['x86_64-w64-mingw32-objdump', '-p', str(dll_path)],
        text=True,
        errors='replace',
    )
    exports = []
    in_name_table = False
    for line in out.splitlines():
        if line.startswith('[Ordinal/Name Pointer] Table -- Ordinal Base 1'):
            in_name_table = True
            continue
        if not in_name_table:
            continue
        m = LINE_RE.match(line)
        if not m:
            if exports and not line.strip():
                break
            continue
        ordinal = int(m.group(1))
        name = m.group(2)
        exports.append((ordinal, name))
    if not exports:
        raise SystemExit(f'no exports parsed from {dll_path}')
    exports.sort(key=lambda x: x[0])
    return exports


def main():
    if len(sys.argv) != 3:
        raise SystemExit(f'usage: {sys.argv[0]} <real_krpt_orig.dll> <out.def>')

    dll_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    exports = parse_exports(dll_path)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8', newline='\n') as f:
        f.write('LIBRARY krpt.dll\n')
        f.write('EXPORTS\n')
        for ordinal, name in exports:
            f.write(f'    {name}=krpt_orig.{name} @{ordinal}\n')

    print(f'export_count={len(exports)}')
    print(f'first={exports[0][0]}:{exports[0][1]}')
    print(f'last={exports[-1][0]}:{exports[-1][1]}')
    print(str(out_path))


if __name__ == '__main__':
    main()
