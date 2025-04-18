# 📋 Clipboard Sync - Real-Time Clipboard Sharing via Network

A Python-based client-server tool for **real-time clipboard synchronization** between multiple devices over a local network or the internet. Now with **end-to-end encryption** for secure communication!

---

## ⚙️ Features

- 🔄 **Two-way clipboard sync**: Syncs clipboard content between the server and multiple clients.
- ⚡ **Real-time updates**: Clipboard changes are immediately broadcast to all connected clients.
- 🔐 **End-to-end encryption**: All clipboard data and socket communication are encrypted using Fernet symmetric encryption.
- 🔁 **Automatic reconnect**: Client automatically reconnects with exponential backoff (2s → 30s, max 15 attempts).
- 🧵 **Multi-threaded handling**: Efficient management of multiple client connections.
- 🖥️ **Cross-platform support**: Works on **Windows, macOS, and Linux**.
- 📝 **Text-only syncing**: This tool syncs only text content. **Files, images, and other media are not supported**.

---

## 🚀 Getting Started

### 📦 Prerequisites

- Python 3.7+
- `pyperclip` library
- `cryptography` library for encryption
- `.env` file for storing the encryption key

---

### ✅ Recommended: Set Up a Virtual Environment

#### **Linux/macOS**

```bash
python3 -m venv [Name_of_venv]
source [Name_of_venv]/bin/activate
```

#### **Windows**

```powershell
python.exe -m venv [Name_of_venv]
.\[Name_of_venv]\Scripts\activate.ps1   # PowerShell
.\[Name_of_venv]\Scripts\activate.bat   # Command Prompt
```

---

### 📥 Install Dependencies

```bash
pip install -r requirements.txt
```

> [!TIP]
> You can also install dependencies manually using:
> `pip install pyperclip cryptography python-dotenv`

---

### 🔑 Generate Encryption Key

Before running the server or client, generate an encryption key to be used for secure communication.

```bash
python generate_key.py
```

- This will generate a new encryption key and store it in a `.env` file.

> [!IMPORTANT]
> Use the same .env file on all devices (clients and server) to ensure encryption works correctly. Copy the file securely to each machine. This will allow the server and clients to communicate securely.

> [!NOTE]  
> The key will be used by both the server and client to encrypt and decrypt clipboard data.

---

### 🖥️ Run the Server

To run the server, specify a custom port (optional):

```bash
python "Clipboard Server.py" --port 65432
```

- Default port is `65432` if no port is provided.

> [!TIP]
> You can run the server in the background using tools like `screen`, `tmux`, or `nohup` to keep it running after closing the terminal.

> [!NOTE]  
> The server monitors clipboard changes, encrypts the clipboard data, and broadcasts updates to connected clients securely.  
> If the connection to the server is lost, the client will attempt to reconnect automatically up to 15 times, starting with a 2-second delay and gradually increasing up to 30 seconds between retries.

---

### 💻 Run the Client

To run the client, connect it to the server by specifying the server's IP and port:

```bash
python "Clipboard Client.py" --ip 127.0.0.1 --port 65432
```

- Default port is `65432` if no port is provided.
- Default IP is `127.0.0.1` if no IP is specified.

> [!TIP]
> Want to auto-start the client at boot? Consider adding it to your OS’s startup tasks or using a script in `crontab`, `systemd`, or Task Scheduler.

> [!NOTE]  
> The client's clipboard will automatically sync with the server and other connected clients, with all communication encrypted.

---

## 🔒 Security Notice

> [!WARNING]  
> This tool **uses encryption** to secure the clipboard data and socket communication. However, please consider the following:
>
> While the data is encrypted during transmission, consider using a **VPN or SSH tunnel** when using over public or untrusted networks to add another layer of security.

> [!CAUTION]  
>
> - Ensure that your `.env` file (which contains the encryption key) is **kept secret** and not shared or committed to version control.  
> - **Do not share sensitive data** using this tool in unsecured environments.

---

## 📄 License

Licensed under the **MIT License** — free to use, modify, and share.
