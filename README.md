# vdump — an IDA Pro plugin that reconstructs C++ class hierarchies from RTTI and dumps all virtual tables into a single, project-ready C++/Python source

## Output
- **`.h`** — a single C++ header.
- *(Optional)* **`.py`** — Python DSL bindings (`manager.virtual_function(...)`) for Source.Python.
  - Enable via: `DUMP_FOR_SOURCE_PYTHON = True`.

## Supported formats
- **PE (NOT TESTED)** (x86/x64), **ELF** (x86/x64), **Mach-O** (x86/x64)

## Requirements
- IDA Pro **9.0+**.
- Hex-Rays decompiler installed (for best signatures; fallback parser works without it).
- Wait for auto-analysis to finish.

## Installation / Run
- Place `vdump.py` into `<IDA>/plugins` or run it as a script.
- Hotkey: **Ctrl+F12**.
