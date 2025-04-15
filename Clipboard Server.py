import socket
import threading
import pyperclip
import time
import hashlib

clients = []
last_clipboard = ""

def get_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def handle_client(conn, addr):
    global last_clipboard
    print(f"[🟢 NEW CONNECTION] {addr} connected.")
    while True:
        try:
            data = conn.recv(4096).decode()
            if data:
                if get_hash(data) != get_hash(last_clipboard):  # Check if clipboard data has changed
                    last_clipboard = data
                    pyperclip.copy(data)  # Update local clipboard
                    print(f"[↓ RECEIVED] Clipboard data from {addr}")
                    broadcast(data, conn)  # Broadcast to other clients
        except socket.error as e:
            print(f"[⚠️ ERROR] Connection error with {addr}: {e}")
            break
        except Exception as e:
            print(f"[⚠️ ERROR] Unexpected error with {addr}: {e}")
            break

def broadcast(data, exclude_conn=None):
    for c in clients:
        if c != exclude_conn:
            try:
                c.sendall(data.encode())  # Send clipboard content to all other clients
            except socket.error as e:
                print(f"[⚠️ ERROR] Failed to send data to a client: {e}")

def clipboard_loop():
    global last_clipboard
    while True:
        time.sleep(0.5)
        try:
            data = pyperclip.paste()
            if get_hash(data) != get_hash(last_clipboard):  # If clipboard data has changed
                last_clipboard = data
                print("[↑ SENT] Clipboard updated locally, broadcasting to clients.")
                broadcast(data)
        except pyperclip.PyperclipException as e:
            print(f"[⚠️ ERROR] Clipboard access error: {e}")

def start_server(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(('0.0.0.0', port))
        server.listen()
        print(f"[🚀 SERVER STARTED] Listening on 0.0.0.0:{port}")
    except socket.error as e:
        print(f"[⚠️ ERROR] Failed to start server on port {port}: {e}")
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
    try:
        start_server(65432)  # Use default port
    except Exception as e:
        print(f"[❌ ERROR] Could not start server: {e}")
