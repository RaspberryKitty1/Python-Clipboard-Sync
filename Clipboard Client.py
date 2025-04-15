import socket
import threading
import pyperclip
import time
import hashlib
import argparse

last_clipboard = ""

def get_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def clipboard_monitor(sock):
    global last_clipboard
    while True:
        time.sleep(0.5)
        try:
            data = pyperclip.paste()
            if get_hash(data) != get_hash(last_clipboard):  # Only send when clipboard changes
                last_clipboard = data
                sock.sendall(data.encode())  # Send the updated clipboard content
                print(f"[↑ SENT] Clipboard data sent to server.")
        except pyperclip.PyperclipException as e:
            print(f"[⚠️ ERROR] Clipboard access error: {e}")
            break
        except socket.error as e:
            print(f"[⚠️ ERROR] Failed to send clipboard data to server: {e}")
            break

def listen_from_server(sock):
    global last_clipboard
    while True:
        try:
            data = sock.recv(4096).decode()  # Receive clipboard data from server
            if not data:
                print("[⚠️ DISCONNECTED] Server closed connection.")
                break
            if get_hash(data) != get_hash(last_clipboard):  # Update clipboard if different
                last_clipboard = data
                pyperclip.copy(data)
                print(f"[↓ RECEIVED] Clipboard data updated from server.")
        except socket.error as e:
            print(f"[⚠️ ERROR] Error receiving data from server: {e}")
            break
        except Exception as e:
            print(f"[⚠️ ERROR] Unexpected error: {e}")
            break

def start_client(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))  # Connect to server IP and port
        print(f"[✅ CONNECTED] Connected to server at {server_ip}:{server_port}")
    except socket.error as e:
        print(f"[❌ FAILED] Could not connect to server: {e}")
        return

    threading.Thread(target=clipboard_monitor, args=(sock,), daemon=True).start()
    listen_from_server(sock)  # Listen for clipboard changes from server

if __name__ == "__main__":
    # Argument parser for IP and port
    parser = argparse.ArgumentParser(description="Clipboard Sync Client")
    parser.add_argument('--ip', type=str, default="127.0.0.1", help="IP address of the server (default: 127.0.0.1)")
    parser.add_argument('--port', type=int, default=65432, help="Port to connect to the server (default: 65432)")
    args = parser.parse_args()

    try:
        start_client(args.ip, args.port)
    except Exception as e:
        print(f"[❌ ERROR] Could not start client: {e}")
