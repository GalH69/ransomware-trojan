END_MARKER = b"__END__"

def send_message(sock, data: bytes):
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    sock.sendall(data + END_MARKER)
    
def send_text(sock, text: str):
        send_message(sock, text.encode("utf-8"))