import socket
import json
import sys

def send_request(sock, request):
    sock.send(json.dumps(request).encode('utf-8'))
    sock.send(b'\x00')
    response = b''
    while True:
        chunk = sock.recv(1 << 20)
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
client.settimeout(60)
client.connect(('127.0.0.1', 19743))

rid += 1
init = send_request(client, {
    "jsonrpc": "2.0", "id": rid, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "phase1-test", "version": "1.0"}}
})
print("PASS initialize:", init['result']['serverInfo'])

rid += 1
tools = send_request(client, {"jsonrpc": "2.0", "id": rid, "method": "tools/list", "params": {}})
names = sorted(t['name'] for t in tools['result']['tools'])
print(f"PASS tools/list ({len(names)} tools)")
expected = {"identify_file", "suggest_patterns", "run_pattern_file", "inspect_data", "disassemble", "list_architectures"}
missing = expected - set(names)
if missing:
    print("FAIL missing Phase 1 tools:", missing); sys.exit(1)
print("PASS all 6 Phase 1 tools registered")

r = call(client, "open_file", {"file_path": "C:/Windows/System32/notepad.exe"})
print(f"PASS open_file: handle={r['handle']} size={r['size']}")

# identify_file (libmagic)
r = call(client, "identify_file")
print(f"PASS identify_file: desc={r['description']!r} mime={r['mime_type']!r} ext={r.get('extensions','')!r} sig={r['signature_match']!r}")

# suggest_patterns
r = call(client, "suggest_patterns")
print(f"PASS suggest_patterns: count={r['count']} first={(r['patterns'][0]['path'] if r['patterns'] else None)!r}")

# inspect_data at the PE header (0x3C holds e_lfanew, a u32)
r = call(client, "inspect_data", {"address": 0x3C, "endian": "little"})
interp = r['interpretations']
print(f"PASS inspect_data @0x3C: u32={interp.get('u32')} bytes_read={r['bytes_read']}")
print(f"     types present: {sorted(interp.keys())}")

# inspect_data type filter
r = call(client, "inspect_data", {"address": 0, "types": ["u16", "char"]})
print(f"PASS inspect_data filter: {r['interpretations']}")

# run_pattern_file — content-independent pattern (no includes): struct over the DOS header.
# Note ImHex syntax: 'in'/'out' come AFTER the variable name.
pat = """
struct DOSHeader {
    char magic[2];
    u8 rest[0x3A];
    u32 pe_offset;
};
DOSHeader header @ 0x00;
u32 lfanew out;
lfanew = header.pe_offset;
"""
r = call(client, "run_pattern_file", {"source": pat})
if '__error__' in r:
    print("FAIL run_pattern_file:", r['__error__'])
else:
    print(f"PASS run_pattern_file: success={r['success']} patterns={r['pattern_count']} out={r['out_variables']}")
    if r['compile_errors']: print("     compile_errors:", r['compile_errors'])
    if r['eval_error']: print("     eval_error:", r['eval_error'])
    if r.get('patterns'): print(f"     pattern tree type: {type(r['patterns']).__name__}, sample: {json.dumps(r['patterns'])[:120]}")

# run_pattern_file with an input variable (declared 'in' so the runtime injects it)
r = call(client, "run_pattern_file", {"source": "u32 base in; u8 b @ 0x00; u32 echo out; echo = base + b;", "in_variables": {"base": 16}})
print(f"PASS run_pattern_file(in_vars): success={r['success']} out={r.get('out_variables')}")
if r['compile_errors']: print("     compile_errors:", r['compile_errors'])

# run_pattern_file error path (bad syntax)
r = call(client, "run_pattern_file", {"source": "this is not valid pattern code @@@"})
print(f"PASS run_pattern_file(error): success={r['success']} compile_errors={len(r['compile_errors'])}")

# list_architectures
r = call(client, "list_architectures")
print(f"PASS list_architectures: {len(r['architectures'])} archs, capstone {r.get('capstone_version')}")

# disassemble the PE entry area as x86-64
r = call(client, "disassemble", {"architecture": "x64", "address": 0, "size": 32, "max_instructions": 6})
if '__error__' in r:
    print("FAIL disassemble:", r['__error__'])
else:
    print(f"PASS disassemble x64: {r['count']} instrs, consumed={r['bytes_consumed']}")
    for insn in r['instructions'][:4]:
        print(f"     0x{insn['address']:08X}: {insn['bytes']:<14} {insn['mnemonic']} {insn['operands']}")

# disassemble arm thumb to prove mode control
r = call(client, "disassemble", {"architecture": "arm;thumb", "address": 0, "size": 16, "max_instructions": 4})
print(f"PASS disassemble arm;thumb: {r['count']} instrs" if '__error__' not in r else f"FAIL: {r['__error__']}")

# disassemble error path (bad arch)
r = call(client, "disassemble", {"architecture": "nonsense-arch"})
print(f"PASS disassemble(error): {r.get('__error__',{}).get('message','?')}")

client.close()
print("\nPHASE 1 SMOKE TEST COMPLETE")
