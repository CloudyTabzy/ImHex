# ImHex MSVC Fork - Agent Instructions

**Repository:** `C:\Dev\ImHex-Project\imhex-fork` (separate git repo within the workspace)  
**Upstream:** [WerWolv/ImHex](https://github.com/WerWolv/ImHex)  
**Fork Origin:** [CloudyTabzy/ImHex](https://github.com/CloudyTabzy/ImHex)  
**Current Version:** `1.39.0.WIP`  
**License:** GPLv2 (with LGPLv2.1 exceptions for libimhex and plugins/ui)

> For the **workspace overview**, workflow rules, and bridge documentation, see the project-root `AGENTS.md` at `C:\Dev\ImHex-Project\AGENTS.md`.

---

## What We Modified in This Fork

This is not a vanilla ImHex build. We are extending it toward an agent-friendly binary RE co-pilot:

| Modification | Files | Status |
|---|---|---|
| **Headless MCP server mode** | `main/gui/source/main.cpp`, `main/gui/source/init/run/desktop.cpp` | ✅ Live — `--mcp-server` launches without GLFW |
| **Native MCP tool surface** | `plugins/builtin/source/content/mcp_tools.cpp` + `romfs/mcp/tools/*.json` | ✅ 21 tools registered |
| **Archive plugin port** | Same as above | ✅ 14 tools adapted from legacy `plugin_mcp.cpp` |
| **Bookmark enumeration API** | `lib/libimhex/include/hex/api/imhex_api/bookmarks.hpp`, `lib/libimhex/source/api/imhex_api.cpp`, `plugins/builtin/source/content/views/view_bookmarks.cpp` | ✅ Added `getEntries()` + `RequestListBookmarks` |
| **Headless crash fixes** | `main/gui/source/init/run/desktop.cpp`, `lib/libimhex/source/ui/imgui_imhex_extensions.cpp` | ✅ TaskManager pump + null-guards |
| **Async provider open fix** | `plugins/builtin/source/content/mcp_tools.cpp` | ✅ `open_file` now waits for open to complete |

### Native MCP Tools (21 total)

**Original 7:**
`open_file`, `list_open_data_sources`, `select_data_source`, `read_data`, `execute_pattern_code`, `get_pattern_console_content`, `get_patterns`

**Ported from archive plugin (14):**
`write_data`, `read_chunked`, `search_bytes`, `search_multiple`, `extract_strings`, `calculate_hash`, `detect_file_type`, `calculate_entropy`, `get_byte_statistics`, `get_provider_info`, `close_file`, `add_bookmark`, `remove_bookmark`, `list_bookmarks`

---

## Environment & Toolchain

### Required Tools

| Tool | Path | Notes |
|------|------|-------|
| **MSVC Build Tools** | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` | VS 2022 Build Tools (v18) |
| **vcpkg** | `C:\vcpkg` | Must set `VCPKG_ROOT` |
| **CMake** | System PATH | 3.25+ |
| **Ninja** | System PATH | Generator |
| **Git** | System PATH | Submodules required |

### vcpkg Dependencies

Managed via `dist/vcpkg.json`:
- libmagic, freetype, mbedtls, zlib, bzip2, liblzma, zstd
- glfw3, curl, libssh2, md4c

### Required Environment

```powershell
$env:VCPKG_ROOT = "C:\vcpkg"
# Optional:
$env:CMAKE_BUILD_TYPE = "Release"
```

---

## Project Layout (ImHex Fork)

```
imhex-fork/
├── CMakeLists.txt                   # Main CMake config
├── CMakePresets.json                # vs2022, vs2022-x86 presets
├── VERSION                          # 1.39.0.WIP
│
├── cmake/                           # Build helpers
│   ├── build_helpers.cmake          # Compiler detection, flags
│   ├── ide_helpers.cmake
│   └── modules/
│       └── ImHexPlugin.cmake
│
├── lib/
│   ├── libimhex/                    # Core LGPL library
│   ├── external/                    # Git submodules
│   │   ├── disassembler/
│   │   ├── libromfs/
│   │   ├── libwolv/
│   │   └── pattern_language/
│   └── third_party/                 # Bundled deps
│       ├── imgui, fmt, nlohmann_json, capstone, glfw3, yara, ...
│
├── main/
│   └── gui/                         # GUI entry point + headless mode
│
├── plugins/
│   ├── builtin/                     # Core plugin (MCP tools live here)
│   ├── ui/, fonts/, decompress/, diffing/, disassembler/, hashes/
│   ├── remote/, script_loader/, visualizers/, windows/, yara_rules/
│
├── tests/                           # Unit tests
├── dist/vcpkg.json                  # Dependency manifest
└── build/vs2022/                    # MSVC output
```

### Key Files for MCP Work

| File | Purpose |
|------|---------|
| `plugins/builtin/source/content/mcp_tools.cpp` | Native MCP tool implementations |
| `plugins/builtin/romfs/mcp/tools/*.json` | Tool JSON schemas |
| `main/gui/source/init/run/desktop.cpp` | Headless `--mcp-server` mode |
| `main/gui/source/main.cpp` | CLI argument parsing |
| `lib/libimhex/include/hex/api/content_registry/communication_interface.hpp` | `ContentRegistry::MCP::registerTool()` |
| `lib/libimhex/include/hex/api/imhex_api/` | Provider, bookmarks APIs |

---

## Build Instructions

### Quick Build (Recommended)

```powershell
$env:VCPKG_ROOT = "C:\vcpkg"
cmake --preset vs2022
cmake --build build/vs2022 --target imhex_all
```

### Manual Build

```powershell
# Run in VS Developer Command Prompt or after vcvarsall.bat x64
$env:VCPKG_ROOT = "C:\vcpkg"

cmake -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_MANIFEST_DIR="..\dist" `
  -DIMHEX_USE_DEFAULT_BUILD_SETTINGS=ON `
  ..

ninja imhex_all
```

### Presets

| Preset | Description | Arch |
|---|---|---|
| `vs2022` | Visual Studio 2022 + vcpkg | x64 |
| `vs2022-x86` | Visual Studio 2022 + vcpkg | x86 |

### Important CMake Options

| Option | Default | Description |
|---|---|---|
| `IMHEX_USE_DEFAULT_BUILD_SETTINGS` | OFF | Use ccache/lld/ninja — set OFF on MSVC |
| `IMHEX_ENABLE_UNIT_TESTS` | ON | Build unit tests |
| `IMHEX_ENABLE_LTO` | OFF | Link-time optimization |
| `IMHEX_STRICT_WARNINGS` | ON | Warnings as errors |
| `IMHEX_BUNDLE_PLUGIN_SDK` | ON | Bundle plugin SDK |

---

## Development Guidelines

### Compiler Compatibility

- **Primary:** MSVC (VS 2022+)
- **Standard:** C++23 (`/std:c++latest`)
- Maintain MSVC compatibility — use guards for GCC/Clang-specific code

### Code Style

- 4-space indentation
- `PascalCase` types, `camelCase` functions/variables, `SCREAMING_SNAKE_CASE` macros
- Prefer `std::` algorithms over raw loops
- Use `hex::` namespace for ImHex APIs

### Plugin Development

- Plugins go in `plugins/`
- Required: `builtin`, `fonts`, `ui`
- Link against `libimhex`

### Windows Notes

- `WIN32_LEAN_AND_MEAN` and `NOMINMAX` are defined globally
- `UNICODE` and `_CRT_SECURE_NO_WARNINGS` are defined globally
- Prefer `std::filesystem` over Win32 APIs
- Stack traces via `dbghelp`

---

## Testing

### C++ Unit Tests

```powershell
cmake --build build/vs2022 --target imhex_all
ctest --test-dir build/vs2022
```

### Native MCP Smoke Tests

```powershell
# 1. Start ImHex headless
.\build\vs2022\imhex-gui.exe --mcp-server

# 2. In another terminal
python test_mcp_tools.py
python test_mcp_file.py
```

### Build Helpers

The repo includes convenience batch files:
- `configure.bat` — run CMake configure
- `build.bat` — build `imhex_all`
- `build_headless.bat` — build and run `--mcp-server`
- `test_version.bat` — quick version check
- `test_mcp_server.bat` — launch headless server

---

## Thread Safety Rules

Any tool that calls ImHex GUI APIs or mutates providers must marshal to the main thread:

```cpp
return TaskManager::doLater([&]() -> nlohmann::json {
    // safe ImHex API calls here
}).get();
```

This applies to:
- `write_data`
- `close_file`
- Bookmark operations
- Any future GUI-mutating tools

---

## Common Issues

### `Your current environment probably needs to be setup to use vcpkg`

Set the environment variable:
```powershell
$env:VCPKG_ROOT = "C:\vcpkg"
```

### `External dependency ... is empty!`

Initialize submodules:
```powershell
git submodule update --init --recursive
```

### `ImHex can only be compiled with GCC or Clang`

This fork has MSVC support. If the error appears, bypass at your own risk:
```powershell
cmake -DIMHEX_IGNORE_BAD_COMPILER=ON ...
```

### LTO Issues

```powershell
cmake -DIMHEX_ENABLE_LTO=OFF ...
```

---

## Production Push

When ready, push to the target fork:

```powershell
& "C:\Program Files\GitHub CLI\gh.exe" auth status
& "C:\Program Files\GitHub CLI\gh.exe" repo view CloudyTabzy/ImHex
& "C:\Program Files\GitHub CLI\gh.exe" pr create --title "feat: MCP binary RE co-pilot" --body "..."
```

**Do not push without explicit user approval.**

---

## Resources

- **Upstream Docs:** [docs.werwolv.net](https://docs.werwolv.net)
- **Pattern Language:** [ImHex-Patterns](https://github.com/WerWolv/ImHex-Patterns)
- **MSVC Support PR:** upstream [v1.37.1 release notes](https://github.com/WerWolv/ImHex/releases/tag/v1.37.1)
- **Workspace Root AGENTS.md:** `C:\Dev\ImHex-Project\AGENTS.md`
- **Live Status Board:** `C:\Dev\ImHex-Project\Docs\project_status_and_workflow.md`
