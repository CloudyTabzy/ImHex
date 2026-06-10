import socket
import json
import time

# Connect to ImHex MCP server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 19743))

# Send initialize request
init_request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "clientInfo": {
            "name": "test-client",
            "version": "1.0.0"
        }
    }
}

client.send(json.dumps(init_request).encode('utf-8'))
client.send(b'\x00')

# Read response
response = b''
while True:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
    if b'\x00' in chunk:
        break

print("Response:", response.split(b'\x00')[0].decode('utf-8'))

# Send tools/list request
list_request = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/list",
    "params": {}
}

client.send(json.dumps(list_request).encode('utf-8'))
client.send(b'\x00')

response = b''
while True:
    chunk = client.recv(4096)
    if not chunk:
        break
    response += chunk
    if b'\x00' in chunk:
        break

print("Tools:", response.split(b'\x00')[0].decode('utf-8'))

client.close()
