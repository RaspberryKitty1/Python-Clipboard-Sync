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

MAX_RETRIES = 5  # Max retry attempts after disconnect
RETRY_DELAY = 2  # Delay before retrying connection

def load_key():
    global fernet
    load_dotenv()
    key = os.getenv("SHARED_KEY")
    if not key:
        raise ValueError("❌ SHARED_KEY not found in .env")
    fernet = Fernet(key.encode())

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

def encrypt_data(data):
    if not fernet:
        raise ValueError("❌ Fernet encryption object is not initialized.")
    return fernet.encrypt(data.encode())

def decrypt_data(data):
    if not fernet:
        raise ValueError("❌ Fernet encryption object is not initialized.")
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
    load_key()  # Ensure the key is loaded before starting clipboard monitor.

    while True:  # Outer loop for reconnection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        attempt = 1

        while attempt <= 15:
            delay = min(2 * attempt, 30)  # Delay increases per attempt, max 30 sec

            try:
                sock.connect((server_ip, server_port))
                print(f"[✅ CONNECTED] Connected to server at {server_ip}:{server_port}")
                break  # Exit retry loop on successful connection
            except socket.error as e:
                print(f"[❌ FAILED] Could not connect to server: {e}")
                if attempt < 15:
                    print(f"[⚠️ Attempting to reconnect (Attempt {attempt}/15) in {delay} seconds...]")
                    time.sleep(delay)
                    attempt += 1
                else:
                    print("[❌ ERROR] Max retry attempts reached. Exiting.")
                    return  # Exit the script after max retries

        # Start threads only if connected successfully
        if attempt <= 15:
            threading.Thread(target=clipboard_monitor, args=(sock,), daemon=True).start()
            listen_from_server(sock)
            print("[⚠️ DISCONNECTED] Server closed connection. Reconnecting...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clipboard Sync Client (Encrypted)")
    parser.add_argument('--ip', type=str, default="127.0.0.1", help="Server IP (default: 127.0.0.1)")
    parser.add_argument('--port', type=int, default=65432, help="Server port (default: 65432)")
    args = parser.parse_args()

    try:
        start_client(args.ip, args.port)
    except ValueError as e:
        print(f"[❌ ERROR] {e}")
