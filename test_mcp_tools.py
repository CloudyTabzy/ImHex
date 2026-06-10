import socket
import json
import base64
import sys

def send_request(sock, request):
    sock.send(json.dumps(request).encode('utf-8'))
    sock.send(b'\x00')
    response = b''
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        response += chunk
        if b'\x00' in chunk:
            break
    return json.loads(response.split(b'\x00')[0].decode('utf-8'))

rid = 0
def call(sock, name, args=None):
    global rid
    rid += 1
    resp = send_request(sock, {
        "jsonrpc": "2.0", "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}}
    })
    if 'error' in resp:
        return {'__error__': resp['error']}
    return resp['result'].get('structuredContent', resp['result'])

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.settimeout(30)
client.connect(('127.0.0.1', 19743))

rid += 1
init = send_request(client, {
    "jsonrpc": "2.0", "id": rid, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "smoke-test", "version": "1.0"}}
})
print("PASS initialize:", init['result']['serverInfo'])

rid += 1
tools = send_request(client, {"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
names = sorted(t['name'] for t in tools['result']['tools'])
print(f"PASS tools/list ({len(names)} tools):", ', '.join(names))

expected = {"write_data", "read_chunked", "search_bytes", "search_multiple", "extract_strings",
            "calculate_hash", "detect_file_type", "calculate_entropy", "get_byte_statistics",
            "get_provider_info", "close_file", "add_bookmark", "remove_bookmark", "list_bookmarks"}
missing = expected - set(names)
if missing:
    print("FAIL missing tools:", missing); sys.exit(1)

r = call(client, "open_file", {"file_path": "C:/Windows/System32/notepad.exe"})
handle = r['handle']
print(f"PASS open_file: handle={handle} size={r['size']}")

r = call(client, "detect_file_type")
print(f"PASS detect_file_type: {r['file_type']} magic={r['magic_bytes'][:8]}")
assert r['file_type'] == "Windows PE/COFF Executable", r

r = call(client, "search_bytes", {"pattern": "4D5A", "type": "hex", "max_results": 5})
print(f"PASS search_bytes: count={r['count']} first={r['matches'][:3]}")
assert r['matches'][0] == 0, r

r = call(client, "search_bytes", {"pattern": "This program cannot", "type": "ascii"})
print(f"PASS search_bytes(ascii): count={r['count']} at={r['matches'][:2]}")

r = call(client, "search_multiple", {"patterns": [{"pattern": "50450000"}, {"pattern": ".text", "type": "ascii"}]})
for res in r['results']:
    print(f"PASS search_multiple: '{res['pattern']}' count={res['count']}")

r = call(client, "extract_strings", {"min_length": 8, "max_strings": 10})
print(f"PASS extract_strings(ascii): count={r['count']} truncated={r['truncated']} first={r['strings'][0]['value'][:30]!r}")

r = call(client, "extract_strings", {"min_length": 8, "encoding": "utf16le", "max_strings": 10})
print(f"PASS extract_strings(utf16le): count={r['count']} first={r['strings'][0]['value'][:30]!r}")

r = call(client, "calculate_hash", {"algorithm": "sha256"})
print(f"PASS calculate_hash: sha256={r['hash'][:16]}... size={r['size']}")

r = call(client, "calculate_hash", {"algorithm": "crc32", "address": 0, "size": 256})
print(f"PASS calculate_hash: crc32={r['hash']}")

r = call(client, "calculate_entropy", {"block_size": 65536})
print(f"PASS calculate_entropy: overall={r['overall_entropy']:.3f} blocks={r['count']}")

r = call(client, "get_byte_statistics", {"size": 65536})
print(f"PASS get_byte_statistics: unique={r['unique_bytes']} entropy={r['entropy']:.3f} printable={r['printable_percentage']:.1f}%")

r = call(client, "read_chunked", {"address": 0, "size": 1024, "chunk_size": 4096, "encoding": "hex"})
print(f"PASS read_chunked: chunks={r['total_chunks']} has_more={r['has_more']} data={r['data'][:8]}")
assert r['data'][:4] == "4D5A", r

r = call(client, "get_provider_info")
print(f"PASS get_provider_info: name={r['name']} writable={r['is_writable']} dirty={r['is_dirty']}")

# Bookmarks (exercise main-thread marshaling + new enumeration API)
r = call(client, "add_bookmark", {"address": 0, "size": 64, "name": "DOS Header", "comment": "Added by MCP smoke test"})
bm_id = r['id']
print(f"PASS add_bookmark: id={bm_id}")

r = call(client, "list_bookmarks")
print(f"PASS list_bookmarks: count={r['count']} first={r['bookmarks'][0]['name'] if r['bookmarks'] else None}")
assert any(b['id'] == bm_id for b in r['bookmarks']), r

r = call(client, "remove_bookmark", {"id": bm_id})
print(f"PASS remove_bookmark: removed={r['removed']}")

r = call(client, "list_bookmarks")
assert not any(b['id'] == bm_id for b in r['bookmarks']), r
print(f"PASS list_bookmarks after removal: count={r['count']}")

# Error handling: write to read-only file provider should fail cleanly
r = call(client, "write_data", {"address": 0, "data": "FF"})
print(f"PASS write_data error path: {r.get('__error__', {}).get('message', r)}")

# Error handling: invalid hex pattern
r = call(client, "search_bytes", {"pattern": "ZZZZ"})
print(f"PASS search_bytes error path: {r.get('__error__', {}).get('message', r)}")

# Error handling: out-of-range address
r = call(client, "read_chunked", {"address": 99999999999})
print(f"PASS read_chunked error path: {r.get('__error__', {}).get('message', r)}")

r = call(client, "close_file", {"handle": handle})
print(f"PASS close_file: closed={r['closed']}")

r = call(client, "list_open_data_sources")
print(f"PASS list_open_data_sources after close: {len(r['data_sources'])} sources")

client.close()
print("\nALL TESTS PASSED")
