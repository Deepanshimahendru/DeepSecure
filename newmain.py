# Designed to securely encrypt files using password-based key derivation
# Focused on usability, safety, and preventing accidental data loss
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
import re
import random
import string

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


#Password => key
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# Checking strength of password
def check_password_strength(password):
    if len(password) < 6:
        return "Too short (min 6 characters)"
    if not re.search(r"[A-Z]", password):
        return "Add at least 1 uppercase letter"
    if not re.search(r"[0-9]", password):
        return "Add at least 1 number"
    if not re.search(r"[!@#$%^&*]", password):
        return "Add at least 1 special character"
    return "Strong"


def suggest_password():
    chars = string.ascii_letters + string.digits + "!@#$%"
    return ''.join(random.choice(chars) for _ in range(10))

 # show or hide password       
def toggle_password():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
    else:
        password_entry.config(show='*')
         #about section
def show_about():
    messagebox.showinfo(
        "About",
        "File Encryption Tool\nBuilt using Python & Tkinter\nImplements secure password-based encryption."
    )
# choose file
def choose_file():
    global selected_file
    file_path = filedialog.askopenfilename()

    if file_path:
        selected_file = file_path
        size = os.path.getsize(file_path) / 1024
        file_label.config(
            text=f"{os.path.basename(file_path)} ({size:.2f} KB)"
        )

def record_activity(action, filename):
    with open("deepsecure_audit.log", "a") as log:
        import datetime
        log.write(f"[{datetime.datetime.now()}] {action}: {filename}\n")

#encryption
def encrypt_file():
    global selected_file

    password = password_entry.get()

    if not selected_file or not password:
        messagebox.showerror("Error", "Select file and enter password")
        return
     
    # password strength check
    strength = check_password_strength(password)

    if strength != "Strong":
        suggestions = [suggest_password() for _ in range(2)]

        response = messagebox.askyesno(
            "Weak Password",
            f"{strength}\n\nTry these:\n" + "\n".join(suggestions) + "\n\nContinue anyway?"
        )

        if not response:
            return

    # generating salt + key
    salt = os.urandom(16) #using 16 coz 32 is way much and 8 is weak
    key = generate_key(password, salt)
    f = Fernet(key)

    # read file
    with open(selected_file, "rb") as file:
        data = file.read()

    encrypted = f.encrypt(data)

    # save encrypted file
    new_file = selected_file + ".enc"

    with open(new_file, "wb") as file:
        file.write(salt + encrypted)   # salt is stored 

    # If user wanna delete original file
    delete = messagebox.askyesno(
        "Delete Original?",
        "Do you want to delete the original file?"
    )

    if delete:
        os.remove(selected_file)

    messagebox.showinfo(
        "Success",
        f"Encrypted file created:\n{os.path.basename(new_file)}"
    )

# decryption
def decrypt_file():
    global selected_file

    password = password_entry.get()

    if not selected_file or not password:
        messagebox.showerror("Error", "Select file and enter password")
        return

    with open(selected_file, "rb") as file:
        file_data = file.read()

    salt = file_data[:16]
    encrypted_data = file_data[16:]

    key = generate_key(password, salt)
    f = Fernet(key)

    try:
        decrypted = f.decrypt(encrypted_data)
    except:
        messagebox.showerror("Error", "Wrong password or corrupted file")
        return

    # save decrypted file
    original_name = selected_file.replace(".enc", "")

    with open(original_name, "wb") as file:
        file.write(decrypted)

    messagebox.showinfo(
        "Success",
        f"Decrypted file restored:\n{os.path.basename(original_name)}"
    )
    # Delete the .enc file after successful restoration
    if os.path.exists(selected_file):
        os.remove(selected_file)


# switching windows
def show_home():
    file_frame.pack_forget()
    home_frame.pack()

def show_file_screen():
    home_frame.pack_forget()
    file_frame.pack()
# gui
root = tk.Tk()
home_frame = tk.Frame(root)
file_frame = tk.Frame(root)
home_frame.pack()
print("==============================")
print("      DEEPSECURE v1.0         ")
print("  Created by [Deepanshi Mahendru]      ")
print("==============================")
tk.Label(home_frame, text="  DeepSecure🔐  ", font=("Arial", 16, "bold")).pack(pady=20)

tk.Button(home_frame, text="Choose File", command=lambda: [choose_file(), show_file_screen()]).pack(pady=10)

tk.Button(home_frame, text="About", command=show_about).pack(pady=5)

tk.Button(home_frame, text="Exit", command=root.quit).pack(pady=10)
tk.Label(file_frame, text="Selected File:", font=("Arial", 12)).pack(pady=5)

file_label = tk.Label(file_frame, text="No file selected")
file_label.pack(pady=5)

tk.Label(file_frame, text="Enter Password").pack(pady=5)

password_entry = tk.Entry(file_frame, show="*", width=30)
password_entry.pack(pady=5)
tk.Button(file_frame, text="Show/Hide Password", command=toggle_password).pack(pady=2)
tk.Button(file_frame, text="Encrypt", command=encrypt_file).pack(pady=10)
tk.Button(file_frame, text="Decrypt", command=decrypt_file).pack(pady=5)

tk.Button(file_frame, text="Back", command=show_home).pack(pady=10)

root.mainloop()