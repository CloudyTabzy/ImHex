import socket
import json
import base64

def send_request(sock, request):
    sock.send(json.dumps(request).encode('utf-8'))
    sock.send(b'\x00')
    response = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        if b'\x00' in chunk:
            break
    return json.loads(response.split(b'\x00')[0].decode('utf-8'))

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 19743))

# Initialize
result = send_request(client, {
    "jsonrpc": "2.0", "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "clientInfo": {"name": "test", "version": "1.0"}}
})
print("Init:", result)

# Open a test file
result = send_request(client, {
    "jsonrpc": "2.0", "id": 2,
    "method": "tools/call",
    "params": {"name": "open_file", "arguments": {"file_path": "C:/Windows/System32/notepad.exe"}}
})
print("Open:", result)

# List open data sources
result = send_request(client, {
    "jsonrpc": "2.0", "id": 3,
    "method": "tools/call",
    "params": {"name": "list_open_data_sources", "arguments": {}}
})
print("List:", result)

# Read first 16 bytes
result = send_request(client, {
    "jsonrpc": "2.0", "id": 4,
    "method": "tools/call",
    "params": {"name": "read_data", "arguments": {"address": 0, "size": 16}}
})
print("Read:", result)
if 'result' in result and 'content' in result['result']:
    data = json.loads(result['result']['content'][0]['text'])
    raw = base64.b64decode(data['data'])
    print("Bytes:", raw.hex())

client.close()
