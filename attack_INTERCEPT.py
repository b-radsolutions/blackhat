import socket

server_conn = socket.create_connection(('localhost', 8000))
client_conn = socket.create_server(('localhost', 8001))
client_conn, _caddr = client_conn.accept()

# Assume this is always on a request-response protocol

while True:
    req = client_conn.recv(4096)
    print(f"Request: {req}")
    # Alter the request here
    server_conn.send(req)
    resp = server_conn.recv(4096)
    print(f"Response: {resp}")
    # Alter the response here
    client_conn.send(resp)