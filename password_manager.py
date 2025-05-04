from tkinter import *
from tkinter import messagebox
import random
import pyperclip
import json
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
import sys

def resource_path(relative_path):
    """Get the absolute path to a resource, works for dev and PyInstaller."""
    if hasattr(sys, '_MEIPASS'):
        # PyInstaller creates a temp folder and stores files in _MEIPASS
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

# Global variables
current_user = None
web_entry = None
email_entry = None
password_entry = None
master_password_hash = None  # Store the master password hash after login

# ---------------------------- MANUAL SHA-256 IMPLEMENTATION ------------------------------- #
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def rotr(x, n):
    """Right rotate x by n bits."""
    return (x >> n) | (x << (32 - n)) & 0xffffffff

def sha256_manual(message):
    """Manual SHA-256 hashing of a string message."""
    msg_bytes = message.encode('utf-8')
    msg_len = len(msg_bytes) * 8

    padding = b'\x80' + b'\x00' * ((56 - (len(msg_bytes) + 1) % 64) % 64)
    msg_len_bytes = (msg_len).to_bytes(8, byteorder='big')
    padded_msg = msg_bytes + padding + msg_len_bytes

    h = H.copy()

    for i in range(0, len(padded_msg), 64):
        chunk = padded_msg[i:i+64]
        w = [0] * 64
        for j in range(16):
            w[j] = int.from_bytes(chunk[j*4:j*4+4], byteorder='big')
        for j in range(16, 64):
            s0 = rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2] >> 10)
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & 0xffffffff

        a, b, c, d, e, f, g, hh = h

        for j in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (hh + S1 + ch + K[j] + w[j]) & 0xffffffff
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            hh = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        h[0] = (h[0] + a) & 0xffffffff
        h[1] = (h[1] + b) & 0xffffffff
        h[2] = (h[2] + c) & 0xffffffff
        h[3] = (h[3] + d) & 0xffffffff
        h[4] = (h[4] + e) & 0xffffffff
        h[5] = (h[5] + f) & 0xffffffff
        h[6] = (h[6] + g) & 0xffffffff
        h[7] = (h[7] + hh) & 0xffffffff

    hash_result = ''.join(f'{x:08x}' for x in h)
    return hash_result

# ---------------------------- AES ENCRYPTION/DECRYPTION ------------------------------- #
def hash_to_bytes(hash_str):
    """Convert a SHA-256 hash string (64 hex chars) to 32 bytes."""
    try:
        return bytes.fromhex(hash_str)
    except ValueError as e:
        print(f"Error converting hash to bytes: {e}")
        return None

def encrypt_password(password, master_password_hash):
    """Encrypt the password using AES-GCM with the master password hash as the key."""
    key = hash_to_bytes(master_password_hash)
    if key is None:
        print("Encryption failed: Invalid master password hash")
        return None
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(password.encode('utf-8')) + encryptor.finalize()
    tag = encryptor.tag  # Get the authentication tag
    return {
        "encrypted_password": base64.b64encode(ciphertext).decode('utf-8'),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }

def decrypt_password(encrypted_data, master_password_hash):
    """Decrypt the password using AES-GCM with the master password hash as the key."""
    try:
        # Validate input
        if not isinstance(encrypted_data, dict) or \
           "encrypted_password" not in encrypted_data or \
           "nonce" not in encrypted_data or \
           "tag" not in encrypted_data:
            print("Decryption failed: Invalid encrypted data format (missing fields)")
            return None
        
        # Decode base64 data
        try:
            ciphertext = base64.b64decode(encrypted_data["encrypted_password"])
            nonce = base64.b64decode(encrypted_data["nonce"])
            tag = base64.b64decode(encrypted_data["tag"])
        except base64.binascii.Error as e:
            print(f"Decryption failed: Base64 decoding error - {e}")
            return None

        # Convert hash to bytes
        key = hash_to_bytes(master_password_hash)
        if key is None:
            print("Decryption failed: Invalid master password hash")
            return None

        # Decrypt with authentication tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')
    except InvalidTag:
        print("Decryption failed: Authentication tag mismatch (wrong key or tampered data)")
        return None
    except Exception as e:
        print(f"Decryption failed: Unexpected error - {e}")
        return None

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def gen_password():
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    nr_letters = random.randint(8, 10)
    nr_symbols = random.randint(2, 4)
    nr_numbers = random.randint(2, 4)

    password_list = [random.choice(letters) for _ in range(nr_letters)]
    password_list += [random.choice(symbols) for _ in range(nr_symbols)]
    password_list += [random.choice(numbers) for _ in range(nr_numbers)]
    
    random.shuffle(password_list)
    password = "".join(password_list)
    
    password_entry.delete(0, END)
    password_entry.insert(0, password)
    pyperclip.copy(password)

# ---------------------------- SAVE PASSWORD ------------------------------- #
def save_password():
    global current_user, master_password_hash
    website = web_entry.get()
    email = current_user
    password = password_entry.get()
    
    if not website or not password:
        messagebox.showinfo(title="Info", message="Incomplete Information")
        return
    
    if master_password_hash is None:
        messagebox.showerror(title="Error", message="No master password hash available. Please log in again.")
        return
    
    # Encrypt the password using the stored master password hash
    encrypted_data = encrypt_password(password, master_password_hash)
    if encrypted_data is None:
        messagebox.showerror(title="Error", message="Encryption failed. Please try again.")
        return
    
    new_password = {
        website: {
            "email": email,
            "encrypted_password": encrypted_data["encrypted_password"],
            "nonce": encrypted_data["nonce"],
            "tag": encrypted_data["tag"]
        }
    }
    
    json_file = f"{email.replace('@', '_').replace('.', '_')}_passwords.json"
    try:
        with open(json_file, mode="r") as file:
            data = json.load(file)
        # Check if website already exists
        if website in data:
            # Prompt user to confirm overwriting
            response = messagebox.askyesno(
                title="Website Exists",
                message=f"Credentials for {website} already exist. Do you want to update the password?"
            )
            if not response:
                return  # User chose not to update, exit function
        # Update or add new password
        data.update(new_password)
        with open(json_file, mode="w") as file:
            json.dump(data, file, indent=4)
    except FileNotFoundError:
        # JSON file doesn't exist, create new
        with open(json_file, mode="w") as file:
            json.dump(new_password, file, indent=4)
    except json.JSONDecodeError:
        # Handle corrupted JSON file
        messagebox.showerror(title="Error", message="Corrupted JSON file. Starting fresh.")
        with open(json_file, mode="w") as file:
            json.dump(new_password, file, indent=4)
            
    finally:
        web_entry.delete(0, END)
        password_entry.delete(0, END)

# ---------------------------- SEARCH PASSWORD ------------------------------- #
def search_password():
    global current_user, master_password_hash
    website = web_entry.get()
    email = current_user
    
    if not website:
        messagebox.showinfo(title="Info", message="Please provide the website")
        return
    
    if master_password_hash is None:
        messagebox.showerror(title="Error", message="No master password hash available. Please log in again.")
        return
    
    json_file = f"{email.replace('@', '_').replace('.', '_')}_passwords.json"
    try:
        with open(json_file, mode="r") as file:
            data = json.load(file)
        
        if website in data:
            if data[website]["email"] == email:
                encrypted_data = {
                    "encrypted_password": data[website]["encrypted_password"],
                    "nonce": data[website]["nonce"],
                    "tag": data[website].get("tag")  # Use .get() to handle legacy data
                }
                if encrypted_data["tag"] is None:
                    messagebox.showerror(title="Error", message="Password data is in an old format. Please save a new password for this website.")
                    return
                decrypted_password = decrypt_password(encrypted_data, master_password_hash)
                if decrypted_password is None:
                    messagebox.showerror(title="Error", message="Failed to decrypt password. Data may be corrupted or incompatible. Please try saving a new password.")
                    return
                dialog = Toplevel()
                dialog.title(website)
                dialog_width = 300
                dialog_height = 150
                screen_width = dialog.winfo_screenwidth()
                screen_height = dialog.winfo_screenheight()
                x = (screen_width - dialog_width) // 2
                y = (screen_height - dialog_height) // 2
                dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
                Label(dialog, text=f"Email: {email}\nPassword: {decrypted_password}", pady=10).pack()
                Button(dialog, text="Copy Password", command=lambda: [pyperclip.copy(decrypted_password), dialog.destroy()], bg="green", fg="white").pack(pady=5)
                Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
                password_entry.delete(0, END)
                password_entry.insert(0, decrypted_password)
            else:
                messagebox.showerror(title="Error", message=f"No account found for {email} on {website}")
        else:
            messagebox.showinfo(title=website, message="No such website exists")
    except:
        messagebox.showinfo(title=website, message="No such website exists")

# ---------------------------- LOGIN PAGE ------------------------------- #
def show_main_app():
    login_window.destroy()
    setup_main_ui()

def login():
    global current_user, master_password_hash
    email = login_email_entry.get()
    password = login_password_entry.get()
    
    if not email or not password:
        messagebox.showinfo(title="Info", message="Please provide email and password")
        return
    
    try:
        with open("users.json", mode="r") as file:
            users = json.load(file)
    except:
        messagebox.showerror(title="Error", message="No users found. Please create an account.")
        return
    
    if email in users:
        hashed_password = sha256_manual(password)
        if users[email]["password"] == hashed_password:
            current_user = email
            master_password_hash = hashed_password  # Store the hash for encryption/decryption
            show_main_app()
        else:
            messagebox.showerror(title="Error", message="Incorrect password")
    else:
        messagebox.showinfo(title="Info", message="No account found. Please create an account.")

def create_account():
    email = login_email_entry.get()
    password = login_password_entry.get()
    
    if not email or not password:
        messagebox.showinfo(title="Info", message="Please provide email and password")
        return
    
    hashed_password = sha256_manual(password)
    new_user = {
        email: {
            "password": hashed_password
        }
    }
    
    try:
        with open("users.json", mode="r") as file:
            users = json.load(file)
        if email in users:
            messagebox.showerror(title="Error", message="Account already exists")
        else:
            users.update(new_user)
            with open("users.json", mode="w") as file:
                json.dump(users, file, indent=4)
            messagebox.showinfo(title="Success", message="Account created! Please log in.")
            login_email_entry.delete(0, END)
            login_password_entry.delete(0, END)
    except:
        with open("users.json", mode="w") as file:
            json.dump(new_user, file, indent=4)
        messagebox.showinfo(title="Success", message="Account created! Please log in.")
        login_email_entry.delete(0, END)
        login_password_entry.delete(0, END)

# ---------------------------- LOGIN UI ------------------------------- #
login_window = Tk()
login_window.title("Login to Password Manager")
login_window.config(padx=20, pady=20, bg="light blue")

# Center the login window
window_width = 400
window_height = 350
screen_width = login_window.winfo_screenwidth()
screen_height = login_window.winfo_screenheight()
x = (screen_width - window_width) // 2
y = (screen_height - window_height) // 2
login_window.geometry(f"{window_width}x{window_height}+{x}+{y}")

canvas = Canvas(width=200, height=200, bg="light blue", highlightthickness=0)
img = PhotoImage(file=resource_path("logo.png"))
canvas.create_image(100, 100, image=img)

canvas.grid(column=0, row=0, columnspan=2)

Label(login_window, text="Email:", bg="light blue").grid(column=0, row=1, sticky="E")
login_email_entry = Entry(login_window, width=40)
login_email_entry.grid(column=1, row=1, pady=5)

Label(login_window, text="Master Password:", bg="light blue").grid(column=0, row=2, sticky="E")
login_password_entry = Entry(login_window, width=40, show="*")
login_password_entry.grid(column=1, row=2, pady=5)

Button(login_window, text="Login", bg="blue", fg="white", width=15, command=login).grid(column=1, row=3, pady=5)
Button(login_window, text="Create Account", bg="green", fg="white", width=15, command=create_account).grid(column=1, row=4, pady=5)

# ---------------------------- MAIN APP UI ------------------------------- #
def setup_main_ui():
    global web_entry, email_entry, password_entry
    
    window = Tk()
    window.title("Password Manager")
    window.config(padx=20, pady=20, bg="light blue")

    # Center the main window
    window_width = 600
    window_height = 400
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    window.geometry(f"{window_width}x{window_height}+{x}+{y}")

    canvas = Canvas(width=200, height=200, bg="light blue", highlightthickness=0)
    img = PhotoImage(file=resource_path("logo.png"))
    canvas.create_image(100, 100, image=img)
    canvas.grid(column=1, row=0)

    label_1 = Label(text="Website: ", bg="light blue")
    label_1.grid(column=0, row=1)

    label_2 = Label(text="Email/Username: ", bg="light blue", pady=10)
    label_2.grid(column=0, row=2)

    label_3 = Label(text="Password: ", pady=10, bg="light blue")
    label_3.grid(column=0, row=3)

    web_entry = Entry()
    web_entry.config(width=32)
    web_entry.grid(column=1, row=1)

    email_entry = Entry()
    email_entry.config(width=50, state="disabled", disabledbackground="#D3D3D3")
    email_entry.grid(column=1, row=2, columnspan=2)
    email_entry.config(state="normal")
    email_entry.insert(0, current_user)
    email_entry.config(state="disabled")

    password_entry = Entry()
    password_entry.config(width=32)
    password_entry.grid(column=1, row=3)

    gen_pass_btn = Button(text="Generate Password", bg="brown", fg="white", command=gen_password)
    gen_pass_btn.grid(column=2, row=3, padx=5)

    search_btn = Button(text="Search", bg="brown", fg="white", command=search_password, width=15)
    search_btn.grid(column=2, row=1)

    add_btn = Button(text="Add", width=42, bg="blue", fg="white", command=save_password)
    add_btn.grid(row=4, column=1, columnspan=2)

    window.mainloop()

login_window.mainloop()