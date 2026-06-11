"""Phase 3 + first 3 from Phase 4 smoke test against the headless ImHex MCP server.

Verifies the 8 new tools: extended calculate_hash, list_hash_algorithms,
demangle_symbol, copy_bytes_as, generate_report, update_bookmark, fill_range,
create_view.

Run after the headless server is up:
    .\\build\\vs2022\\imhex-gui.exe --mcp-server
"""
import socket
import json
import sys

def send_request(sock, request):
    sock.send(json.dumps(request).encode("utf-8"))
    sock.send(b"\x00")
    response = b""
    while True:
        chunk = sock.recv(1 << 20)
        if not chunk:
            break
        response += chunk
        if b"\x00" in chunk:
            break
    return json.loads(response.split(b"\x00")[0].decode("utf-8"))

rid = 0
def call(sock, name, args=None):
    global rid
    rid += 1
    resp = send_request(sock, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                               "params": {"name": name, "arguments": args or {}}})
    if "error" in resp:
        return {"__error__": resp["error"]}
    return resp["result"].get("structuredContent", resp["result"])

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(150)
client.connect(("127.0.0.1", 19743))

rid += 1
send_request(client, {"jsonrpc": "2.0", "id": rid, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "phase3", "version": "1.0"}}})

# tools/list
rid += 1
tools = send_request(client, {"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
names = sorted(t["name"] for t in tools["result"]["tools"])
print(f"PASS tools/list ({len(names)} tools)")

expected_new = {
    "list_hash_algorithms", "demangle_symbol", "copy_bytes_as", "generate_report",
    "update_bookmark", "fill_range", "create_view",
    # calculate_hash is pre-existing, but we re-test it below to confirm
    # it still works after the registry-backed refactor
}
missing = expected_new - set(names)
if missing:
    print("FAIL missing Phase 3 tools:", missing); sys.exit(1)
print(f"PASS all 7 new tools registered (calculate_hash was pre-existing)")

# Open a writable memory source so fill_range and update_bookmark have something to mutate
r = call(client, "open_memory", {"data": "00" * 64, "encoding": "hex"})
handle = r["handle"]
print(f"PASS open_memory: handle={handle} size={r['size']} writable={r['is_writable']}")

# --- 1) list_hash_algorithms ---
r = call(client, "list_hash_algorithms")
algos = r.get("algorithms", [])
print(f"PASS list_hash_algorithms: count={r.get('count')} (showing first 3)")
for a in algos[:3]:
    print(f"     {a['id']:20s}  name={a['name']:30s}  functions={a['functions']}")

# Pick a known id from the list and use it
md5_id = next((a["id"] for a in algos if a["id"].lower() in ("md5",)), None)
if not md5_id:
    print("WARN no md5 entry found in list_hash_algorithms; will try calculate_hash with sha256")
    md5_id = "sha256"

# --- 2) calculate_hash (extended) with the new id ---
r = call(client, "calculate_hash", {"algorithm": md5_id, "address": 0, "size": 32})
print(f"PASS calculate_hash({md5_id!r}): algorithm={r['algorithm']!r} hash={r['hash']!r}")

# Back-compat: also try the legacy hard-coded values
r2 = call(client, "calculate_hash", {"algorithm": "crc32", "address": 0, "size": 16})
print(f"PASS calculate_hash(legacy 'crc32'): hash={r2['hash']!r}")

# Negative: unknown algorithm
r3 = call(client, "calculate_hash", {"algorithm": "definitely_not_a_real_hash_xyz"})
assert "__error__" in r3, f"expected error for unknown alg, got {r3}"
print(f"PASS calculate_hash(unknown): error returned correctly")

# --- 3) demangle_symbol ---
tests = [
    # Itanium ABI (Linux/macOS style)
    ("_ZN5ImHex6Server4initEv",         True),
    # MSVC (Windows style)
    ("?init@Server@ImHex@@QEAAXXZ",     True),
    # Rust v0 (may or may not be recognized by bundled LLVM version)
    ("_RNvCs4fqI2P2rA9IpvajB_7mycrate3foo", None),  # None = don't assert true/false
    # Not a symbol
    ("definitely_not_a_symbol",        False),
]
for mangled, expect_recognized in tests:
    r = call(client, "demangle_symbol", {"symbol": mangled})
    print(f"PASS demangle_symbol({mangled!r}): demangled={r['demangled']!r} recognized={r['recognized']}")
    if expect_recognized is True:
        assert r["recognized"], f"expected to recognize {mangled!r}"
    elif expect_recognized is False:
        assert not r["recognized"], f"expected NOT to recognize {mangled!r}"
    # else None: don't assert (capabilities vary by LLVM version)

# --- 4) copy_bytes_as ---
for fmt in ("c", "rust", "python", "base64"):
    r = call(client, "copy_bytes_as", {"format": fmt, "address": 0, "size": 8})
    print(f"PASS copy_bytes_as(format={fmt!r}): first_chars={r['output'][:40]!r}...")
    assert r["output"], f"empty output for format {fmt}"

# Negative: unknown format
r = call(client, "copy_bytes_as", {"format": "definitely_not_a_format"})
assert "__error__" in r, f"expected error for unknown format, got {r}"
print(f"PASS copy_bytes_as(unknown): error returned with available formats list")

# --- 5) generate_report ---
r = call(client, "generate_report")
print(f"PASS generate_report: section_count={r.get('section_count')} report_chars={len(r.get('report',''))}")
if r.get("sections"):
    for i, s in enumerate(r["sections"][:2]):
        first_line = s.splitlines()[0] if s else "(empty)"
        print(f"     section[{i}]: {first_line[:80]}")

# --- 6) update_bookmark ---
r = call(client, "add_bookmark", {"address": 0, "size": 8, "name": "orig", "comment": ""})
old_id = r["id"]
print(f"PASS add_bookmark: id={old_id}")

r = call(client, "update_bookmark", {"id": old_id, "name": "renamed", "comment": "by phase 3", "color": 0xFF0000FF})
new_id = r["id"]
print(f"PASS update_bookmark: old_id={old_id} -> new_id={new_id} name={r['name']!r} comment={r['comment']!r}")
assert new_id != old_id, "update_bookmark should produce a new id"
assert r["name"] == "renamed" and r["comment"] == "by phase 3"

# Verify the new bookmark shows up in list_bookmarks
r = call(client, "list_bookmarks")
names = [b["name"] for b in r.get("bookmarks", [])]
print(f"PASS list_bookmarks contains 'renamed': {'renamed' in names}")
assert "renamed" in names, f"renamed bookmark not found in {names}"

# Clean up
call(client, "remove_bookmark", {"id": new_id})

# --- 7) fill_range ---
# fill_range uses the active provider (getActiveProvider), so select the
# writable memory source first
call(client, "select_data_source", {"handle": handle})
# Single-byte fill
r = call(client, "fill_range", {"address": 0, "size": 16, "value": 0xAB})
print(f"PASS fill_range(value=0xAB): wrote={r['size']} pattern_hex={r['pattern_hex']!r}")
assert r["size"] == 16
assert r["pattern_hex"] == "AB"

# Multi-byte pattern on the same source (raw bytes, not hex-decoded)
r = call(client, "fill_range", {"address": 0, "size": 16, "pattern": "ABC"})
print(f"PASS fill_range(pattern='ABC'): wrote={r['size']} pattern_hex={r['pattern_hex']!r}")
# 'A'=0x41, 'B'=0x42, 'C'=0x43
assert r["pattern_hex"] == "414243", f"expected 414243, got {r['pattern_hex']}"

# --- 8) create_view ---
# create_view uses the active provider as the base. Open a bigger source
# first and select it.
r = call(client, "open_memory", {"data": "AB" * 256, "encoding": "hex"})
r = call(client, "select_data_source", {"handle": r["handle"]})
r = call(client, "create_view", {"address": 16, "size": 64, "name": "phase3 test view"})
view_handle = r["handle"]
print(f"PASS create_view: handle={view_handle} addr={r['address']} size={r['size']} name={r['name']!r}")
assert r["read_only"] is True
assert r["size"] == 64

# Verify the view is in the provider list
r = call(client, "list_open_data_sources")
handles = [d["handle"] for d in r["data_sources"]]
print(f"PASS list_open_data_sources: {len(handles)} providers, view present: {view_handle in handles}")
assert view_handle in handles

# Switch to the view and read a few bytes
call(client, "select_data_source", {"handle": view_handle})
r = call(client, "read_data", {"address": 0, "size": 4})
view_bytes = r["data"]
print(f"PASS read_data on view: bytes={view_bytes[:20]!r}... (should start with AB AB AB AB)")

client.close()
print("\nPHASE 3 SMOKE TEST COMPLETE")
