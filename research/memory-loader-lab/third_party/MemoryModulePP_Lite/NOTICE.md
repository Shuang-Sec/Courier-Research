# MemoryModulePP_Lite notice

This directory is a MinGW-compatible learning adapter for the local CTF memory-loading lab.

Why it exists:

- The upstream `bb107/MemoryModulePP` project is MSVC-oriented and uses Windows/PHNT/MSVC SEH constructs that do not compile in the current Linux + MinGW-only lab toolchain.
- The user still wants to learn and test a MemoryModulePP-style path for loading the direct_https DLL from memory.

What this adapter does:

- Implements the core PE-in-memory loading flow used in this lab: copy headers/sections, apply relocations, resolve imports, set memory protections, call the DLL entry point, resolve exports, and unload.
- Keeps the public API separate from the older `third_party/MemoryModule` code so tests can explicitly say they used the `MemoryModulePP_Lite` loader path.

What this adapter does **not** do:

- It is not a full replacement for upstream MemoryModulePP.
- It does not implement full SEH/C++ exception support, Ldr list insertion, full reference counting, or the two advanced TLS modes from upstream MemoryModulePP.

References:

- Upstream MemoryModulePP: https://github.com/bb107/MemoryModulePP — MIT License.
- Classic MemoryModule ideas: https://github.com/fancycode/MemoryModule — MPL.
