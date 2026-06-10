# ImHex MSVC Fork + MCP Binary RE Co-Pilot - Agent Instructions

## Project Overview

This is a dual-purpose project:

1. **ImHex MSVC Fork**: Building and maintaining ImHex using **MSVC (Microsoft Visual C++)** on Windows, moving away from the traditional GCC/Clang/MinGW toolchain.
2. **Standalone MCP Binary RE Server**: A production-ready Python MCP (Model Context Protocol) server that gives AI agents direct tool access to binary analysis capabilities, eliminating the "write me a script" loop for reverse engineering work.

- **Upstream**: [WerWolv/ImHex](https://github.com/WerWolv/ImHex)
- **Fork Origin**: [CloudyTabzy/ImHex](https://github.com/CloudyTabzy/ImHex)
- **Current Version**: `1.39.0.WIP`
- **License**: GPLv2 (with LGPLv2.1 exceptions for libimhex and plugins/ui)

### MSVC Support Context

MSVC support was officially added to upstream ImHex in **v1.37.1 (February 2025)** thanks to [@mrexodia](https://github.com/mrexodia). This fork is based on a post-v1.37.1 version and already contains all the necessary MSVC build infrastructure. The upstream README may still claim MSVC is unsupported - **this is outdated**. This fork is explicitly intended for MSVC builds.

### MCP Server Architecture Decision

**We are NOT using the [imhexMCP](https://github.com/jmpnop/imhexMCP) approach.** imhexMCP patches ImHex core (14 patches), adds a C++ network plugin, and wraps ImHex via TCP. While innovative, this is fragile against upstream changes.

**Our approach**: A **hybrid Python MCP Bridge** (`imhex-mcp-bridge`) that:
1. Connects to ImHex's **native MCP server** (port 19743, TCP) when available
2. Falls back to **pure Python analysis tools** (mmap + Construct) when ImHex is not running
3. Exposes **stdio transport** for OpenCode/Claude/Cursor compatibility

**Key insight**: ImHex v1.39.0 already has a built-in MCP server (`hex::mcp::Server`). We leverage it instead of patching. The bridge acts as a stdio-to-TCP proxy + analysis enhancer.

**Key difference**: 
- imhexMCP: patches ImHex, exposes internals directly
- Our bridge: **zero patches**, optional ImHex coupling, works standalone

---

## Environment & Toolchain

### Required Tools (User-Specific Paths)

| Tool | Path | Notes |
|------|------|-------|
| **MSVC Build Tools** | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` | Visual Studio 2022 Build Tools (v18) |
| **vcpkg** | `C:\vcpkg` | Must have `VCPKG_ROOT` env var set to this path |
| **CMake** | System PATH | 3.25+ required |
| **Ninja** | System PATH | Used as the generator |
| **Git** | System PATH | Required for submodule cloning |

### vcpkg Dependencies

Dependencies are managed via `dist/vcpkg.json`:
- libmagic, freetype, mbedtls, zlib, bzip2, liblzma, zstd
- glfw3, curl, libssh2, md4c

### Important Environment Variables

```powershell
# Required
$env:VCPKG_ROOT = "C:\vcpkg"

# Optional but recommended
$env:CMAKE_BUILD_TYPE = "Release"  # or "Debug", "RelWithDebInfo"
```

---

## Project Layout

```
imhex-fork/                          # Project Root
├── CMakeLists.txt                   # Main CMake configuration
├── CMakePresets.json                # Build presets (includes vs2022, vs2022-x86)
├── VERSION                          # Current version: 1.39.0.WIP
│
├── cmake/                           # CMake modules and helpers
│   ├── build_helpers.cmake          # Core build logic, compiler detection, flags
│   ├── ide_helpers.cmake            # IDE integration helpers
│   ├── cmake_uninstall.cmake.in     # Uninstall target template
│   ├── modules/                     # Find*.cmake modules
│   │   ├── FindCapstone.cmake
│   │   ├── FindMagic.cmake
│   │   ├── FindmbedTLS.cmake
│   │   ├── ImHexPlugin.cmake        # Plugin build macros
│   │   └── ... (11 more)
│   └── sdk/                         # SDK generation helpers
│
├── lib/                             # Libraries and dependencies
│   ├── libimhex/                    # Core library (LGPL) - Plugin API
│   ├── trace/                       # Tracing library
│   ├── external/                    # External git submodules
│   │   ├── disassembler/            # Disassembler library
│   │   ├── libromfs/                # ROM filesystem library
│   │   ├── libwolv/                 # Wolv utility library
│   │   └── pattern_language/        # Pattern Language parser/evaluator
│   └── third_party/                 # Bundled third-party libraries
│       ├── imgui/                   # Dear ImGui
│       ├── fmt/                     # Formatting library
│       ├── nlohmann_json/           # JSON library
│       ├── boost/                   # Boost (regex only)
│       ├── capstone/                # Disassembly framework
│       ├── glfw3/                   # Windowing library
│       ├── nativefiledialog/        # File dialogs
│       ├── lunasvg/                 # SVG rendering
│       ├── llvm-demangle/           # LLVM demangler
│       ├── HashLibPlus/             # Hash algorithms
│       ├── miniaudio/               # Audio playback
│       ├── microtar/                # TAR extraction
│       ├── md4c/                    # Markdown parser
│       ├── edlib/                   # Edit distance library
│       ├── xdgpp/                   # XDG directories
│       └── yara/                    # YARA rule engine
│
├── main/                            # Main executable
│   ├── CMakeLists.txt
│   ├── gui/                         # GUI application entry point
│   ├── updater/                     # Auto-updater
│   └── forwarder/                   # Windows forwarder executable
│
├── plugins/                         # Built-in plugins
│   ├── builtin/                     # REQUIRED - Core functionality
│   ├── ui/                          # REQUIRED - UI components (LGPL)
│   ├── fonts/                       # REQUIRED - Font management
│   ├── decompress/                  # Decompression support
│   ├── diffing/                     # File diffing
│   ├── disassembler/                # Disassembler plugin
│   ├── hashes/                      # Hashing tools
│   ├── remote/                      # Remote file providers
│   ├── script_loader/               # Scripting support
│   ├── visualizers/                 # Data visualizers
│   ├── windows/                     # Windows-specific tools
│   └── yara_rules/                  # YARA rule scanning
│
├── tests/                           # Unit tests
│   ├── algorithms/
│   ├── common/
│   ├── helpers/
│   └── plugins/
│
├── dist/                            # Distribution and packaging
│   ├── vcpkg.json                   # vcpkg manifest
│   ├── compiling/                   # Build guides
│   │   ├── windows.md               # Windows/MinGW guide (OUTDATED for MSVC)
│   │   ├── linux.md
│   │   ├── macos.md
│   │   └── ...
│   ├── windows/                     # Windows installer assets
│   ├── macOS/                       # macOS bundle assets
│   └── ... (packaging for various platforms)
│
├── resources/                       # Application resources
│   ├── dist/                        # Distribution resources (icons, themes)
│   ├── projects/                    # Example projects
│   └── resource.rc                  # Windows resource file
│
├── .github/                         # GitHub Actions workflows
├── .clang-tidy                      # Clang-tidy configuration
└── docs/ (implicit via submodules)  # Documentation

# (Sibling/Sub-project) MCP Binary RE Server
Docs/mcp_re_workflow_design.md         # Full design spec for the MCP server
```

**Note**: The MCP bridge (`imhex-mcp-bridge`) is a separate Python package living in the sibling directory. It connects to ImHex's native MCP server via TCP (port 19743) and provides stdio transport for MCP clients. When ImHex is unavailable, it falls back to pure Python tools using `mmap` + Construct.

---

## Build Instructions (MSVC)

### Prerequisites

1. Install **Visual Studio 2022 Build Tools** with C++ workload
2. Install **vcpkg** at `C:\vcpkg` and bootstrap it
3. Install **CMake** (3.25+) and **Ninja**
4. Clone with submodules:
   ```powershell
   git clone --recurse-submodules https://github.com/CloudyTabzy/ImHex.git
   cd ImHex
   ```

### Quick Build (Recommended)

Using the provided CMake preset:

```powershell
# Set required environment variable
$env:VCPKG_ROOT = "C:\vcpkg"

# Configure with MSVC preset
cmake --preset vs2022

# Build
cmake --build build/vs2022 --target imhex_all

# Install (optional)
cmake --build build/vs2022 --target install
```

### Manual Build (Advanced)

```powershell
# Ensure you're in a Visual Studio Developer Command Prompt
# or have run: & "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64

$env:VCPKG_ROOT = "C:\vcpkg"

mkdir build
cd build

cmake -G Ninja `
  -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_MANIFEST_DIR="..\dist" `
  -DIMHEX_USE_DEFAULT_BUILD_SETTINGS=ON `
  ..

ninja imhex_all
```

### Available CMake Presets

| Preset | Description | Architecture |
|--------|-------------|--------------|
| `vs2022` | Visual Studio 2022 with vcpkg | x64 |
| `vs2022-x86` | Visual Studio 2022 with vcpkg | x86 |
| `x86_64` | GCC/Clang base preset (Linux) | x64 |
| `xcode` | Xcode with Clang (macOS) | x64/ARM64 |

### Important Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `IMHEX_USE_DEFAULT_BUILD_SETTINGS` | OFF | Use recommended build tools (ccache, lld, ninja) |
| `IMHEX_STATIC_LINK_PLUGINS` | OFF | Statically link all plugins into main executable |
| `IMHEX_ENABLE_UNIT_TESTS` | ON | Build unit tests |
| `IMHEX_ENABLE_LTO` | OFF | Enable Link Time Optimization |
| `IMHEX_STRICT_WARNINGS` | ON | Treat warnings as errors |
| `IMHEX_BUNDLE_PLUGIN_SDK` | ON | Bundle Plugin SDK in install package |
| `IMHEX_GENERATE_PDBS` | OFF | Generate PDB files in non-debug builds |

**Note**: When building with MSVC, set `IMHEX_USE_DEFAULT_BUILD_SETTINGS=OFF` or it will try to use lld/llvm-ar which may not be available in MSVC environments.

---

## Development Rules & Guidelines

### Compiler Compatibility

- **Primary Target**: MSVC (Visual Studio 2022+)
- **C++ Standard**: C++23 (`/std:c++latest` on MSVC)
- **The fork should maintain MSVC compatibility** - do not introduce GCC/Clang-specific code without MSVC guards
- The `verifyCompiler()` function in `cmake/build_helpers.cmake` already accepts MSVC

### Code Style

- Follow existing ImHex code style
- Use 4-space indentation
- Use `PascalCase` for types, `camelCase` for functions/variables, `SCREAMING_SNAKE_CASE` for macros
- Prefer `std::` algorithms over raw loops
- Use `hex::` namespace for ImHex-specific APIs

### Plugin Development

- All plugins must be in the `plugins/` directory
- Required plugins: `builtin`, `fonts`, `ui` (build will fail without these)
- Plugins link against `libimhex`
- The Plugin SDK is generated during build when `IMHEX_BUNDLE_PLUGIN_SDK=ON`

### Windows-Specific Notes

- Use `WIN32_LEAN_AND_MEAN` and `NOMINMAX` (already defined globally)
- Use `UNICODE` and `_CRT_SECURE_NO_WARNINGS` (already defined globally)
- Prefer `std::filesystem` over Windows API for path operations
- Stack traces are available on Windows via `dbghelp`

### Testing

- Unit tests are in `tests/`
- Enable with `IMHEX_ENABLE_UNIT_TESTS=ON`
- Run with: `ctest --test-dir build/vs2022`

---

## What We Learned from imhexMCP

The [imhexMCP](https://github.com/jmpnop/imhexMCP) project proved that AI + ImHex integration is viable. Here is what they did best (we reference these ideas, but do not adopt their architecture):

| imhexMCP Approach | What We Learned | Our Different Approach |
|---|---|---|
| **28 JSON-RPC endpoints** over TCP (`localhost:31337`) | Binary analysis needs structured, programmatic access | **45 MCP tools** via stdio (MCP protocol) |
| **Queue-based async file opening** via `TaskManager::doLater()` | Threading safety when calling ImHex GUI APIs from network threads | Not applicable — we are not inside ImHex; we use `mmap` directly |
| **C++ plugin + 14 patches to ImHex core** | Full integration is powerful but fragile against upstream changes | **Zero patches** — standalone Python server |
| **Python MCP client with connection pooling, LRU caching, zstd compression** | Production patterns: retry logic, circuit breakers, compression | We will implement similar resilience in our MCP server |
| **Batch operations** (hash/search/diff across multiple files) | Cross-corpus analysis is essential | Built into our `corpus.*` tool surface |
| **Entropy analysis, string extraction, magic number detection** | These are standard RE operations that should be first-class tools | Included in `bytes.*` and `crypto.*` tools |
| **255/255 tests, performance profiling, property-based testing** | Quality matters for RE tools | We target the same standard |

### Why We Rejected Their Architecture

1. **Patch fragility**: 14 patches to ImHex core break on every upstream update
2. **Build complexity**: Requires building ImHex + applying patches + building plugin
3. **Platform lock**: Their setup scripts target macOS/Linux; Windows is "untested"
4. **Coupling**: The MCP server cannot run without ImHex binary running
5. **No persistence**: Session state lives only while ImHex is open

### What We Adopted

- **Endpoint/tool taxonomy**: Their 28 endpoints map closely to our 45 tools
- **Error handling philosophy**: Structured JSON responses, typed errors
- **Performance mindset**: Caching, compression, chunked reading for large files
- **Testing rigor**: 100% pass rate target, property-based testing with Hypothesis

---

## MCP Bridge Development Notes

### Architecture

```
OpenCode / Claude / Cursor (stdio client)
    │ MCP protocol over stdio
    ▼
imhex-mcp-bridge (Python FastMCP)
    ├─> TCP (port 19743) ──> ImHex MCP Server (C++, when available)
    │                          └─7 native tools: open_file, read_data, 
    │                            execute_pattern_code, etc.
    │
    └─> mmap (fallback) ──> Binary files on disk (when ImHex unavailable)
       └─10 Python tools: bytes_read, bytes_search, bytes_entropy, 
         file_identify, pe_info, struct_parse, etc.
```

### Key Design Decisions

| Decision | Rationale |
|---|---|
| **Hybrid bridge** | Uses ImHex when available, falls back to Python when not |
| **FastMCP stdio** | Official Python SDK, handles MCP protocol automatically |
| **TCP proxy** | ImHex native server speaks TCP; bridge translates to stdio |
| **mmap for I/O** | Fast random access for files < 500MB |
| **Construct for schemas** | Powerful binary struct parsing without new DSL |

### Implemented Tool Surface (28 tools)

| Category | Tools | Status |
|---|---|---|
| **ImHex Native** (7 tools) | `open_file`, `list_open_data_sources`, `select_data_source`, `read_data`, `execute_pattern_code`, `get_pattern_console_content`, `get_patterns` | ✅ Live |
| **File** (1 tool) | `file_identify` (magic byte detection) | ✅ Fallback |
| **Bytes** (7 tools) | `bytes_read`, `bytes_hash`, `bytes_entropy`, `bytes_search`, `bytes_strings`, `bytes_read_as`, `bytes_crc32` | ✅ Fallback |
| **Analysis** (3 tools) | `bytes_distribution`, `bytes_entropy_map`, `bytes_diff` | ✅ Fallback |
| **Encoding** (2 tools) | `bytes_encode`, `bytes_decode` | ✅ Fallback |
| **Parsing** (3 tools) | `struct_parse` (Construct), `pe_info`, `elf_info` | ✅ Fallback |
| **Meta** (5 tools) | `imhex_status`, `list_modules`, `list_tools`, `describe_tool`, `invoke_tool` | ✅ Bridge |

### Lazy Mode

**Status:** ✅ Implemented and tested

Instead of exposing all 28 tools in `tools/list` (which consumes ~8K tokens), the bridge now exposes only 4 meta-tools (~1.5K tokens):

| Meta-Tool | Purpose |
|---|---|
| `list_modules` | Discover tool categories (file, bytes, analysis, encoding, parsing) |
| `list_tools` | Search/filter tools by keyword or module |
| `describe_tool` | Get full input schema for any tool |
| `invoke_tool` | Execute any tool by name with nested parameters |

**Result:** ~86% context reduction. Agent discovers tools on-demand.

### Implementation Status

| Phase | What | Status |
|---|---|---|
| **0** | Validate native MCP server connectivity | ✅ Done |
| **1** | Build Python bridge with stdio transport | ✅ Done |
| **2** | Add fallback tools (read, search, entropy) | ✅ Done |
| **3** | Add advanced fallback tools (PE, ELF, Construct) | ✅ Done |
| **4** | Test bridge in hybrid mode (ImHex + Python) | ✅ Done |
| **5** | Lazy mode (4 meta-tools) | ✅ Done |
| **6** | TOON encoding + Session persistence | 🔄 Planned |

### Dependencies

```toml
[project]
dependencies = [
    "mcp>=1.26",        # MCP SDK (FastMCP)
    "construct>=2.10",  # Struct parsing
]
```

---

## Common Issues & Troubleshooting

### vcpkg Not Found

**Error**: `Your current environment probably needs to be setup to use vcpkg`

**Solution**: Ensure `VCPKG_ROOT` environment variable is set:
```powershell
$env:VCPKG_ROOT = "C:\vcpkg"
```

### Missing Submodules

**Error**: `External dependency ... is empty!`

**Solution**: Initialize submodules:
```powershell
git submodule update --init --recursive
```

### Compiler Not Supported

**Error**: `ImHex can only be compiled with GCC or Clang`

**Solution**: This fork should already have MSVC support in `verifyCompiler()`. If you see this error, the `IMHEX_IGNORE_BAD_COMPILER` option can bypass it (not recommended):
```powershell
cmake -DIMHEX_IGNORE_BAD_COMPILER=ON ...
```

### LTO Issues with MSVC

If Link Time Optimization causes issues, disable it:
```powershell
cmake -DIMHEX_ENABLE_LTO=OFF ...
```

---

## Workflow Rules for Agents

### Git Discipline

**The ImHex fork is a git repository.** Every substantial implementation must be committed. Do not leave working changes uncommitted for long.

1. **Commit after substantial implementation**
   - New feature / tool group: commit
   - Major documentation update: commit
   - Bug fix with tests: commit
   - Refactor that touches multiple files: commit

2. **Commit scope**
   - **ImHex C++ changes**: commit inside `imhex-fork/` (this is the git repo)
   - **Bridge Python changes**: commit at project root `C:\Dev\ImHex-Project` (initialize if needed)
   - **Docs changes**: commit at project root alongside bridge changes

3. **Commit message style** (follow conventional commits):
   ```
   feat(mcp): add write_data and search_bytes native tools
   fix(bridge): correct parameter order for default arguments
   docs(setup): add OpenCode MCP configuration guide
   test(lazy): add stdio integration tests for meta-tools
   ```

4. **Before committing, always check**:
   ```powershell
   git status
   git diff --stat
   git log --oneline -5
   ```

5. **Never commit** secrets, build artifacts, or large binaries.

### Documentation Placement

| Location | What Goes There |
|---|---|
| `imhex-fork/AGENTS.md` | Agent instructions, toolchain, build commands, quick reference |
| `Docs/` | Architecture decisions, setup guides, feature analysis, project status, plans |
| `Docs/Archived_(Do_Not_Delete)/` | Old designs and reference material |
| `imhex-mcp-bridge/README.md` | Bridge-specific usage and installation |

**Rule:** Any overview, plan, archive, or status document goes in `Docs/`. Keep `AGENTS.md` as a working reference for agents, not a project wiki.

### TODO/Status Tracking

Maintain `Docs/project_status_and_workflow.md` as the live status board. After each commit:
- Update the status table with checkmarks and notes
- Link to the relevant commit hash
- Mark next priorities clearly

### Code Verification Before Commit

For C++ changes:
```powershell
cmake --build build/vs2022 --target imhex_all
# Run relevant tests
python test_mcp_tools.py
```

For Python bridge changes:
```powershell
cd ..\imhex-mcp-bridge
pip install -e .
python test_comprehensive.py
python test_lazy_mode.py
python test_stdio_integration.py
```

---

## Agent Quick Reference

### Before Making Changes

1. Check `cmake/build_helpers.cmake` for compiler-specific logic
2. Verify changes work with both `Debug` and `Release` configurations
3. Ensure `VCPKG_ROOT` is set before running CMake commands
4. Test builds with: `cmake --build build/vs2022 --target imhex_all`

### Key Files to Know

| File | Purpose |
|------|---------|
| `CMakeLists.txt` | Main build configuration |
| `CMakePresets.json` | Build presets including MSVC |
| `cmake/build_helpers.cmake` | Compiler detection, flags, macros |
| `dist/vcpkg.json` | Dependency manifest |
| `lib/libimhex/` | Core library API |
| `main/gui/` | Main application |
| `plugins/` | All built-in plugins |
| `plugins/builtin/source/content/mcp_tools.cpp` | Native MCP tool implementations |
| `Docs/mcp_re_workflow_design.md` | Full MCP server design spec |
| `Docs/imhex_mcp_architecture.md` | Architecture decision record |
| `Docs/archive_plugin_adaptation_guide.md` | Archive plugin feature extraction |

### Build Verification Commands (ImHex)

```powershell
# Full clean build
$env:VCPKG_ROOT = "C:\vcpkg"
cmake --preset vs2022
cmake --build build/vs2022 --target imhex_all

# With install
 cmake --build build/vs2022 --target install
```

### MCP Bridge Quick Start

```powershell
# Navigate to bridge directory
cd ..\imhex-mcp-bridge

# Install in editable mode
pip install -e .

# Run bridge (stdio transport for OpenCode/Claude)
imhex-mcp-bridge

# Or directly
python -m imhex_mcp_bridge
```

### OpenCode Configuration

Add to your OpenCode config (`~/.config/opencode/opencode.json`):

```json
{
  "mcpServers": {
    "imhex-bridge": {
      "command": "python",
      "args": ["-m", "imhex_mcp_bridge"],
      "env": {}
    }
  }
}
```

### Testing the Bridge

```powershell
# Test fallback mode (standalone)
python test_fallback.py

# Test with ImHex running
# 1. Start ImHex headless: imhex-gui.exe --mcp-server
# 2. Run: python test_bridge_with_imhex.py

# Full comprehensive test
python test_comprehensive.py
```

---

## Contact & Resources

- **Fork Maintainer**: [@CloudyTabzy](https://github.com/CloudyTabzy)
- **Upstream Author**: [@WerWolv](https://github.com/WerWolv)
- **Upstream Docs**: [docs.werwolv.net](https://docs.werwolv.net)
- **Pattern Language**: [ImHex-Patterns](https://github.com/WerWolv/ImHex-Patterns)
- **Original MSVC Support PR**: See upstream [v1.37.1 release notes](https://github.com/WerWolv/ImHex/releases/tag/v1.37.1)
