END_MARKER = b"__END__"

def send(sock, data: bytes | str):
    if isinstance(data, str):
        data = data.encode("utf-8")  # הופך טקסט לבייטים
    elif not isinstance(data, bytes):
        raise ValueError("send() only accepts str or bytes")

    sock.sendall(data + END_MARKER)

def receive(sock) -> bytes:
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer += chunk
        if buffer.endswith(END_MARKER):
            break

    return buffer.removesuffix(END_MARKER)