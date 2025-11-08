END_MARKER = "__END__"

def send(sock, message: str):
    if not isinstance(message, str):
        raise ValueError("Only strings are allowed in send()")
    
    sock.sendall((message + END_MARKER).encode("utf-8"))
    
def receive(sock) -> str:
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer += chunk
        if buffer.endswith(END_MARKER.encode("utf-8")):
            break

    return buffer.decode("utf-8").removesuffix(END_MARKER)