### Compiling ImHex on Windows (MSVC)

This fork builds with **Visual Studio 2022** (MSVC) on Windows.

#### Prerequisites

1. **Visual Studio 2022 Build Tools** or full Visual Studio 2022 (Community/Pro/Enterprise) with the "Desktop development with C++" workload.
2. **vcpkg** — installed at `C:\vcpkg` (or set `VCPKG_ROOT` to your install path).
3. **CMake** 3.25+ and **Ninja** on your PATH.
4. **Git** — clone with `--recurse-submodules`.

#### Build Steps

```powershell
# Set vcpkg root (or add to your profile)
$env:VCPKG_ROOT = "C:\vcpkg"

# Configure and build
cmake --preset vs2022
cmake --build build/vs2022 --target imhex_all
```

The output binary will be at `build/vs2022/imhex-gui.exe`.

#### Launch Headless MCP Server

```powershell
.\build\vs2022\imhex-gui.exe --mcp-server
```

#### Notes

- The `vs2022` CMake preset handles vcpkg integration automatically.
- For Release builds, set `$env:CMAKE_BUILD_TYPE = "Release"` before configuring.
- ImHex will look for extra resources next to the executable or in `%localappdata%/imhex`.
