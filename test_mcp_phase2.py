"""Phase 2 + content-unlock smoke test against the headless ImHex MCP server.

Verifies: libmagic now works (content provisioned), PL std-library includes resolve,
and the new tools auto_analyze / yara_scan / open_memory / diff_data_sources.
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
                      "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "phase2", "version": "1.0"}}})

rid += 1
tools = send_request(client, {"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
names = sorted(t["name"] for t in tools["result"]["tools"])
print(f"PASS tools/list ({len(names)} tools)")
expected = {"auto_analyze", "yara_scan", "open_memory", "diff_data_sources"}
missing = expected - set(names)
if missing:
    print("FAIL missing Phase 2 tools:", missing); sys.exit(1)
print("PASS all 4 Phase 2 tools registered")

call(client, "open_file", {"file_path": "C:/Windows/System32/notepad.exe"})

# --- Content unlock: libmagic should now return a real description ---
r = call(client, "identify_file")
print(f"PASS identify_file: description={r['description']!r} mime={r['mime_type']!r}")
libmagic_works = bool(r["description"])
print(f"     -> libmagic {'ACTIVE' if libmagic_works else 'still empty (content not provisioned?)'}")

# --- Content unlock: PL std-library include should now resolve ---
r = call(client, "run_pattern_file", {"source": "#include <std/mem.pat>\nu32 sz = std::mem::size();\nu32 out_sz out; out_sz = sz;"})
inc_ok = r.get("success") and not any("mem.pat" in (e.get("message","")) for e in r.get("compile_errors", []))
print(f"PASS run_pattern_file(+std include): success={r['success']} std_lib_resolved={inc_ok}")
if r.get("compile_errors"): print("     compile_errors:", r["compile_errors"][:2])

# --- auto_analyze ---
r = call(client, "auto_analyze")
ident = r.get("identification", {})
print(f"PASS auto_analyze: id={ident.get('signature_match')!r} suggested={r.get('suggested_count')} "
      f"applied={'yes' if 'applied_pattern' in r else 'no'}")
if r.get("applied_pattern"):
    ap = r["applied_pattern"]
    print(f"     applied pattern: {ap.get('path','?').split(chr(92))[-1].split('/')[-1]} success={ap.get('success')} fields={ap.get('pattern_count')}")

# --- yara_scan ---
yrule = 'rule mz_header { strings: $mz = "MZ" condition: $mz at 0 }'
r = call(client, "yara_scan", {"rule": yrule})
if "__error__" in r:
    print("FAIL yara_scan:", r["__error__"])
else:
    print(f"PASS yara_scan: {r['rule_count']} rule(s) matched")
    for mr in r["matched_rules"][:2]:
        print(f"     rule '{mr['identifier']}' tags={mr['tags']} matches={mr['match_count']}")

# --- open_memory + use it through the toolchain ---
r = call(client, "open_memory", {"data": "4D5A9000DEADBEEF", "encoding": "hex"})
mem_handle = r["handle"]
print(f"PASS open_memory: handle={mem_handle} size={r['size']} writable={r['is_writable']}")
r = call(client, "inspect_data", {"address": 0, "types": ["u16", "char"]})
print(f"PASS inspect_data on memory source: {r['interpretations']}")

# --- diff_data_sources: diff the memory source against a second one ---
r2 = call(client, "open_memory", {"data": "4D5A9001DEADBEEF", "encoding": "hex"})
mem_handle2 = r2["handle"]
r = call(client, "diff_data_sources", {"handle_a": mem_handle, "handle_b": mem_handle2})
if "__error__" in r:
    print("FAIL diff_data_sources:", r["__error__"])
else:
    print(f"PASS diff_data_sources: algo={r['algorithm']} diffs={r.get('difference_count')} "
          f"regions_a={r.get('differences_a')}")

client.close()
print("\nPHASE 2 SMOKE TEST COMPLETE")
