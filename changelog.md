# Changelog

All notable changes to this fork are documented here. This fork extends upstream ImHex with a comprehensive MCP (Model Context Protocol) tool surface that makes every ImHex analysis feature callable by AI agents.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased] — MCP Tool Surface Expansion

### Added — MCP Tool Surface (50 tools total)

This release extends the native MCP server from 7 tools to **50 tools** across 12 categories, making the full ImHex analysis engine scriptable from any MCP-compatible AI client.

#### Core Analysis Tools (Phase 1) — `54e871a`

- `identify_file` — real libmagic identification (description/MIME/extensions) with signature-table fallback
- `suggest_patterns` — find viable Pattern Language files for the open binary
- `run_pattern_file` — execute Pattern Language (inline source or `.hexpat` path); returns parsed field tree as JSON, in/out variables, compile/eval errors with line+column
- `inspect_data` — 21 native typed interpretations (ints 8/16/24/32/48/64-bit, f32/f64, bool, char, ULEB128, unix time32/64, UUID/GUID), endian-aware
- `disassemble` — Capstone-backed, 20+ architectures (x86, ARM, MIPS, PowerPC, RISC-V, WebAssembly, M68K, etc.) with full mode/endian control via spec strings
- `list_architectures` — enumerate supported ISAs and spec vocabulary

#### Workflow & Content Unlock (Phase 2) — `a0c2a8f`

- `auto_analyze` — one-shot identify → suggest → run best pattern → parsed field tree (e.g., PE → dos.hexpat → 56 fields in a single call)
- `yara_scan` — YARA rule matching with inline rule text or `.yar` path; tags, metadata, per-string match regions
- `open_memory` — in-memory data source from agent-supplied hex/base64/ascii bytes (MemoryFileProvider), selectable like any other provider
- `diff_data_sources` — structural diff of two handles (Simple + Myers algorithms) via the Diffing registry
- **Headless content unlock** — `--mcp-server` now compiles the libmagic `.mgc` database at startup and honors `IMHEX_CONTENT_DIR`; `provision_content.ps1` fetches ImHex-Patterns content (magic, includes, patterns, encodings, constants, nodes)

#### Breadth & Ergonomics (Phase 3) — `4ea8a89`

- `calculate_hash` — extended to 73 algorithms via ContentRegistry::Hashes registry (Blake2, XXHash, Murmur, SipHash, Tiger, CRC family, etc.) with back-compat fallback
- `list_hash_algorithms` — enumerate all 73 registered hash algorithms with friendly ids and available functions
- `demangle_symbol` — Itanium/MSVC/Rust/D demangler via LLVM trace::demangle
- `copy_bytes_as` — format a region using DataFormatter registry entries (C, C++, Rust, Python, Java, C#, Go, Lua, JS, Swift, Pascal, Crystal, base64, hex view, HTML)
- `generate_report` — aggregate all registered Reports generators into markdown
- `update_bookmark` — modify bookmark name/comment/color
- `fill_range` — fill a range with a single-byte value or multi-byte pattern (1 MiB streaming chunks)
- `create_view` — read-only sub-range ViewProvider for safe agent-side inspection without mutation risk

#### Hex Editor Annotations (Phase 4A) — `8a867ee`

- `add_highlight` / `remove_highlight` / `list_highlights` — color-coded background/foreground regions in the hex editor
- `set_selection` / `get_selection` — hex editor cursor/selection control for guiding human review
- `add_tooltip` / `remove_tooltip` — hover annotations with custom text and color

#### Search, Export, and Composite Analysis (Phase 5) — `4ad736d`

- `search_value` — scan provider for numeric values (8/16/32/64-bit, little/big endian, signed/unsigned, exact match or range)
- `export_region` — export a byte range to a file on disk
- `data_info` — composite analysis report (libmagic ID + entropy + byte statistics + header typed interpretations) in one call
- `func_profile` — heuristic code region analysis (instruction count, basic block count, call/jump/return counts, entry point detection)

#### Region Comparison — `7dbf45f`

- `compare_regions` — read two regions from the same data source and compare them byte-by-byte. Returns similarity percentage, matching/differing byte counts, SHA256 of each region, size delta, and the first N differing offsets with byte values. Fills the gap between `read_data` (single region) and `diff_data_sources` (two separate files). Useful for finding embedded duplicates (version strings, repeated configs), detecting code reuse within a single binary, and checking if a region was patched. [R] (pure read, no main-thread marshaling needed).

#### Archive Plugin Port — `474ad3f`

14 foundational tools ported from the legacy MCP plugin to the modern `ContentRegistry::MCP::registerTool()` API:

- `write_data`, `read_chunked` (paginated reads, 16 MiB chunks)
- `search_bytes`, `search_multiple` — Boyer-Moore-Horspool, cross-boundary match detection
- `extract_strings` — ASCII + UTF-16LE, cross-chunk state machine
- `calculate_hash` (initial CRC32/MD5/SHA1/SHA224/SHA256/SHA384/SHA512 implementations)
- `detect_file_type` — 40+ magic signatures
- `calculate_entropy` — exact Shannon entropy (fixes quantized lookup table out-of-bounds errors in the legacy plugin)
- `get_byte_statistics`, `get_provider_info`, `close_file`
- `add_bookmark`, `remove_bookmark`, `list_bookmarks`

### Added — libimhex API Surface

- `ImHexApi::Bookmarks::getEntries()` + `RequestListBookmarks` event — unblocks bookmark enumeration that the legacy plugin had stubbed out
- `hex_editor.hpp` integration — exposes `ImHexApi::HexEditor` for highlight/selection/tooltip management via MCP

### Added — Headless Mode

- `--mcp-server` CLI flag launches ImHex without GLFW, running the MCP TCP server on port 19743
- JSON-RPC 2.0 protocol, `2025-06-18` MCP version
- TCP keepalive (`SO_KEEPALIVE`, `TCP_KEEPIDLE=10s`, `TCP_KEEPINTVL=30s`) for stable long-lived connections
- GUI status indicator in the title bar showing MCP connection state and client info

### Added — Build & Development Tooling — `41b5afd`

- `configure.bat` — CMake configure with vcpkg toolchain
- `build.bat` — Ninja MSVC build
- `build_headless.bat` — configure + build + launch `--mcp-server`
- `test_version.bat` — quick version check
- `test_mcp_server.bat` — launch headless MCP server

### Fixed

- **Async provider open** — `open_file` now waits for the provider to become readable instead of returning a handle with size=0
- **Main-thread marshaling** — all tools that mutate GUI state (bookmarks, highlights, tooltips, providers, reports) marshal to the main thread via `TaskManager::doLater()` + `std::promise/future`
- **Headless crash fixes** — `TaskManager::runDeferredCalls()` pump + null-guards in imgui extensions
- **Capstone stringToSettings()** — empty option token in spec strings no longer rejected with "Unknown disassembler option ''"
- **calculate_entropy precision** — replaced quantized lookup table (which produced out-of-bounds accesses for uniform blocks and ~17% error) with exact Shannon entropy computation
- **run_pattern_file callback** — detaches the console log callback after execution so the shared runtime never holds a dangling reference on the next call

### Documentation

- `AGENTS.md` — refactored to focus on ImHex-specific build notes, MCP tool catalog (21 tools at time of writing), MSVC instructions, thread safety rules, and common build issues — `f74436e`
- `Docs/imhex_capabilities_mcp_adaptation.md` — capability mapping doc with full tool inventory and risk assessment
- `Docs/archive_plugin_adaptation_guide.md` — porting guide used to migrate the legacy MCP plugin's 14 tools to the modern `ContentRegistry::MCP` API

---

## [Upstream] — ImHex v1.39.0.WIP

This fork is based on [WerWolv/ImHex](https://github.com/WerWolv/ImHex) v1.39.0.WIP. All upstream features, fixes, and changes are inherited from the upstream repository. See the upstream changelog for details.

### Fork Origin

- **Maintainer:** [CloudyTabzy](https://github.com/CloudyTabzy)
- **Upstream:** [WerWolv/ImHex](https://github.com/WerWolv/ImHex)
- **Purpose:** Extend ImHex with a first-class MCP tool surface for AI agent integration, while maintaining full compatibility with upstream ImHex's GUI and feature set.
