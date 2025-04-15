import socket
import threading
import pyperclip
import time
import hashlib
import argparse
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

last_clipboard = ""
fernet = None  

# 🔐 Load encryption key from .env
def load_key():
    global fernet
    load_dotenv()
    key = os.getenv("SHARED_KEY")
    if not key:
        raise ValueError("❌ SHARED_KEY not found in .env")
    fernet = Fernet(key.encode())

# 📥 Receive exactly n bytes from socket
def recv_all(sock, length):
    data = b''
    while len(data) < length:
        try:
            packet = sock.recv(length - len(data))
            if not packet:
                return None
            data += packet
        except socket.error:
            return None
    return data

# 🔐 Encrypt the data before sending over the socket
def encrypt_data(data):
    return fernet.encrypt(data.encode())

# 🔐 Decrypt the data after receiving from the socket
def decrypt_data(data):
    return fernet.decrypt(data).decode()

def get_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def clipboard_monitor(sock):
    global last_clipboard
    while True:
        time.sleep(0.5)
        try:
            data = pyperclip.paste()
            if get_hash(data) != get_hash(last_clipboard):
                last_clipboard = data
                encrypted = encrypt_data(data)
                header = len(encrypted).to_bytes(4, 'big')
                sock.sendall(header + encrypted)
                print(f"[↑ SENT] Encrypted clipboard data sent to server.")
        except pyperclip.PyperclipException as e:
            print(f"[⚠️ ERROR] Clipboard access error: {e}")
            break
        except socket.error:
            print(f"[⚠️ ERROR] Failed to send data to server.")
            break

def listen_from_server(sock):
    global last_clipboard
    while True:
        try:
            header = recv_all(sock, 4)
            if not header:
                print("[⚠️ DISCONNECTED] Server closed connection.")
                break
            msg_len = int.from_bytes(header, 'big')
            encrypted_data = recv_all(sock, msg_len)
            if encrypted_data is None:
                break

            try:
                data = decrypt_data(encrypted_data)
            except Exception:
                print(f"[⚠️ ERROR] Decryption failed.")
                continue

            if get_hash(data) != get_hash(last_clipboard):
                last_clipboard = data
                pyperclip.copy(data)
                print(f"[↓ RECEIVED] Clipboard updated from server.")
        except socket.error:
            print(f"[⚠️ ERROR] Error receiving data from server.")
            break

def start_client(server_ip, server_port):
    load_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))
        print(f"[✅ CONNECTED] Connected to server at {server_ip}:{server_port}")
    except socket.error:
        print(f"[❌ FAILED] Could not connect to server.")
        return

    threading.Thread(target=clipboard_monitor, args=(sock,), daemon=True).start()
    listen_from_server(sock)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clipboard Sync Client (Encrypted)")
    parser.add_argument('--ip', type=str, default="127.0.0.1", help="Server IP (default: 127.0.0.1)")
    parser.add_argument('--port', type=int, default=65432, help="Server port (default: 65432)")
    args = parser.parse_args()

    try:
        start_client(args.ip, args.port)
    except ValueError as e:
        print(f"[❌ ERROR] {e}")
