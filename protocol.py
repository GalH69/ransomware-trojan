MAX_LEN = 65535  # כי 2 bytes length (0..65535)

def _recv_exact(sock, n):
    """קורא בדיוק n בתים מהסוקט (TCP). אם החיבור נסגר באמצע -> זורק שגיאה."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:  # b""
            raise ConnectionError("Socket closed while receiving data")
        data += chunk
    return data


def send(sock, data):
    """
    שולח הודעה:
    [2 bytes length][payload]
    data יכול להיות bytes או str.
    """
    if isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray)):
        payload = bytes(data)
    else:
        raise TypeError("send() accepts only str or bytes")

    length = len(payload)
    if length > MAX_LEN:
        raise ValueError(f"Payload too large ({length}). Max is {MAX_LEN} for 2-byte length.")

    header = length.to_bytes(2, byteorder="big")  # 2 bytes
    sock.sendall(header + payload)


def receive(sock):
    """
    מקבל הודעה:
    קורא 2 bytes -> length
    ואז קורא length bytes -> payload
    מחזיר bytes.
    """
    header = _recv_exact(sock, 2)
    length = int.from_bytes(header, byteorder="big")

    if length > MAX_LEN:
        raise ValueError(f"Invalid length received: {length}")

    payload = _recv_exact(sock, length)
    return payload