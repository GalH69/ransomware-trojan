END_MARKER = "__END__"

def send(sock, data):
    if type(data) is str:
        message = data + END_MARKER
        sock.sendall(message.encode("utf-8"))
    elif type(data) is bytes:
        message = data + END_MARKER.encode("utf-8")
        sock.sendall(message)
    else:
        raise ValueError("Only str or bytes are allowed in send()")

def receive(sock):
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer += chunk
        if buffer.endswith(END_MARKER.encode("utf-8")):
            break
    return buffer.decode("utf-8").removesuffix(END_MARKER)