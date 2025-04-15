import socket
import threading
import pyperclip
import time
import hashlib
import argparse
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os

clients = []
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

def handle_client(conn, addr):
    global last_clipboard
    print(f"[🟢 NEW CONNECTION] {addr} connected.")
    try:
        while True:
            # Receive the header (length of the encrypted data)
            header = recv_all(conn, 4)
            if not header:
                break

            # Extract the message length from the header
            msg_len = int.from_bytes(header, 'big')

            # Receive the encrypted data
            encrypted_data = recv_all(conn, msg_len)
            if encrypted_data is None:
                break

            # Decrypt the data
            try:
                data = decrypt_data(encrypted_data)
            except Exception:
                print(f"[⚠️ ERROR] Decryption failed from {addr}")
                continue

            # Check if clipboard is different from last known
            if get_hash(data) != get_hash(last_clipboard):
                last_clipboard = data
                pyperclip.copy(data)
                print(f"[↓ RECEIVED] Clipboard data from {addr}")
                broadcast(data, exclude_conn=conn)
    except socket.error as e:
        print(f"[⚠️ ERROR] Connection error with {addr}: {e}")
    finally:
        print(f"[❌ DISCONNECTED] {addr} removed.")
        if conn in clients:
            clients.remove(conn)
        try:
            conn.close()
        except:
            pass

def broadcast(data, exclude_conn=None):
    try:
        encrypted = encrypt_data(data)
    except Exception:
        print(f"[⚠️ ERROR] Encryption failed.")
        return

    header = len(encrypted).to_bytes(4, 'big')
    message = header + encrypted

    dead_clients = []
    for c in clients:
        if c != exclude_conn:
            try:
                c.sendall(message)
            except socket.error as e:
                print(f"[⚠️ ERROR] Failed to send to client: {e}")
                dead_clients.append(c)
    
    for c in dead_clients:
        if c in clients:
            clients.remove(c)
            try:
                c.close()
            except:
                pass

def clipboard_loop():
    global last_clipboard
    while True:
        time.sleep(0.5)
        try:
            data = pyperclip.paste()
            if get_hash(data) != get_hash(last_clipboard):
                last_clipboard = data
                print("[↑ SENT] Clipboard updated locally, broadcasting to clients.")
                broadcast(data)
        except pyperclip.PyperclipException as e:
            print(f"[⚠️ ERROR] Clipboard access error: {e}")

def start_server(host, port):
    load_key()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((host, port))
        server.listen()
        print(f"[🚀 SERVER STARTED] Listening on {host}:{port}")
    except socket.error as e:
        print(f"[⚠️ ERROR] Failed to start server on {host}:{port}: {e}")
        return

    threading.Thread(target=clipboard_loop, daemon=True).start()

    try:
        while True:
            conn, addr = server.accept()
            clients.append(conn)
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[🛑 SHUTTING DOWN] Server is stopping...")
        for c in clients:
            try:
                c.shutdown(socket.SHUT_RDWR)
                c.close()
            except socket.error as e:
                print(f"[⚠️ ERROR] Failed to close connection: {e}")
        server.close()
        print("[✅ CLOSED] Server shut down cleanly.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clipboard Sync Server (Encrypted)")
    parser.add_argument('--ip', type=str, default="0.0.0.0", help="IP to bind to (default: 0.0.0.0)")
    parser.add_argument('--port', type=int, default=65432, help="Port to bind to (default: 65432)")
    args = parser.parse_args()

    try:
        start_server(args.ip, args.port)
    except ValueError as e:
        print(f"[❌ ERROR] {e}")
