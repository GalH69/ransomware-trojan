END_MARKER = "__END__"

def send(sock, data):
    if isinstance(data, str):
        message = data + END_MARKER
        sock.sendall(message.encode("utf-8"))
    elif isinstance(data, bytes):
        sock.sendall(data)
    else:
        raise ValueError("Only str or bytes are allowed in send()")

def receive(sock, expect_bytes=False):
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer += chunk
        if not expect_bytes and buffer.endswith(END_MARKER.encode("utf-8")):
            break

    if expect_bytes:
        return buffer
    else:
        return buffer.decode("utf-8").removesuffix(END_MARKER)