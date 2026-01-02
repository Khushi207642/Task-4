from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os
import tkinter as tk
from tkinter import filedialog, messagebox

# --- Encryption and Decryption Functions ---
def encrypt_file(file_path, password):
    key = PBKDF2(password, b'salt1234', dkLen=32)  # AES-256 key
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        data = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(data)
    
    encrypted_file = file_path + '.enc'
    with open(encrypted_file, 'wb') as f:
        [f.write(x) for x in (cipher.nonce, tag, ciphertext)]
    return encrypted_file

def decrypt_file(file_path, password):
    key = PBKDF2(password, b'salt1234', dkLen=32)
    with open(file_path, 'rb') as f:
        nonce, tag, ciphertext = [f.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    
    decrypted_file = file_path.replace('.enc', '.dec')
    with open(decrypted_file, 'wb') as f:
        f.write(data)
    return decrypted_file

# --- GUI Functions ---
def browse_file():
    file_path.set(filedialog.askopenfilename())

def encrypt_action():
    try:
        encrypted_file = encrypt_file(file_path.get(), password.get())
        messagebox.showinfo("Success", f"File encrypted:\n{encrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    try:
        decrypted_file = decrypt_file(file_path.get(), password.get())
        messagebox.showinfo("Success", f"File decrypted:\n{decrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- GUI Setup ---
root = tk.Tk()
root.title("Advanced Encryption Tool")
root.geometry("500x250")

file_path = tk.StringVar()
password = tk.StringVar()

tk.Label(root, text="Select File:").pack(pady=5)
tk.Entry(root, textvariable=file_path, width=50).pack()
tk.Button(root, text="Browse", command=browse_file).pack(pady=5)

tk.Label(root, text="Enter Password:").pack(pady=5)
tk.Entry(root, textvariable=password, show="*").pack()

tk.Button(root, text="Encrypt", command=encrypt_action, width=20, bg="green", fg="white").pack(pady=10)
tk.Button(root, text="Decrypt", command=decrypt_action, width=20, bg="blue", fg="white").pack()

root.mainloop()
