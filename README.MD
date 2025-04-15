# 📋 Clipboard Sync - Real-Time Clipboard Sharing via Network

A simple Python-based client-server tool for **real-time clipboard synchronization** between multiple devices over a local network or the internet.

---

## ⚙️ Features

- 🔄 **Two-way clipboard sync**: Syncs clipboard content between the server and multiple clients.
- ⚡ **Real-time updates**: Clipboard changes are immediately broadcast to all connected clients.
- 🔐 **Change detection**: Uses SHA-256 hashing to detect clipboard changes securely.
- 📡 **Broadcast system**: Distributes clipboard updates to all connected clients.
- 🧵 **Multi-threaded handling**: Efficient management of multiple client connections.
- 🖥️ **Cross-platform support**: Works on **Windows, macOS, and Linux**.
- 📝 **Text-only syncing**: This tool syncs only text content. **Files, images, and other media are not supported**.

---

## 🚀 Getting Started

### 📦 Prerequisites

- Python 3.7+
- `pyperclip` library

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

### 📥 Install Dependencies

```bash
pip install -r requirements.txt
```

> [!NOTE] This project currently only requires `pyperclip`, but using `requirements.txt` allows for easy expansion with more dependencies in the future.

---

### 🖥️ Run the Server

To run the server, specify a custom port (optional):

```bash
python "Clipboard Server.py" --port 65432
```

- Default port is `65432` if no port is provided.
- The server monitors clipboard changes and broadcasts updates to connected clients.

---

### 💻 Run the Client

To run the client, connect it to the server by specifying the server's IP and port:

```bash
python "Clipboard Client.py" --ip 127.0.0.1 --port 65432
```

- Default port is `65432` if no port is provided.
- Default IP is `127.0.0.1` if no IP is specified.
- The client's clipboard will automatically sync with the server and other connected clients.

---

## 🔒 Security Notice

> [!WARNING] This tool **does not use encryption**. If using over public or untrusted networks:
>
> - **Use a VPN or SSH tunnel** to secure the connection.
> - **Do not share sensitive data** using this tool in unsecured environments.

---

## 📄 License

Licensed under the **MIT License** — free to use, modify, and share.
