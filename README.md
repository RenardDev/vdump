# vdump — an IDA Pro plugin that reconstructs C++ class hierarchies from RTTI and dumps all virtual tables into a single, project-ready C++ header

## Output
- A directory named after the IDA database (without its extension).
- **`_vdump_common.h`** — shared C++20 helpers and forward declarations.
- One **`<class>.h`** file per generated class.

Generated C++ methods use `void` by default and accept an explicit return type
when needed, for example `ptr->EnableInput<bool>(true)`. Argument types can be
overridden independently with a 1-based index:

```cpp
ptr->Method<void, vdump::arg<4, void*>>(a1, a2, a3, ptr64, a5);
ptr->Method<void, vdump::arg<5, void*>>(a1, a2, a3, a4, ptr64);
```

Argument types are read from demangled names first, then from Hex-Rays and IDA
prototypes as fallbacks. Return type defaults to `void`.

## Supported formats
- **PE (NOT TESTED)** (x86/x64), **ELF** (x86/x64), **Mach-O** (x86/x64)

## Requirements
- IDA Pro **9.0+**.
- Hex-Rays decompiler installed.
- C++20 for consuming generated headers.
- Wait for auto-analysis to finish.

## Installation / Run
- Place `vdump.py` into `<IDA>/plugins` or run it as a script.
- Hotkey: **Ctrl+F12**.
