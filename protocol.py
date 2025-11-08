END_MARKER = b"__END__"

def send(sock, message: str):
    if not isinstance(message, str):
        raise ValueError("Only strings are allowed in send()")
    
    sock.sendall((message + END_MARKER).encode("utf-8"))