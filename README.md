# Flask-SocketIO Chat App with Authentication

This project is a **secure chat application** built using **Flask** and **Flask-SocketIO**. 
It includes **user authentication** (register and login) and runs over HTTPS using a **self-signed SSL certificate**. 
The chat uses **ECDH key exchange** and **ChaCha20 encryption** for ecryption.


## Requirements

Before running the project, make sure you have:

- **Python 3.11+**
- **pip**


## Setup Instructions

1. Download the project folder.

2. Install required Python packages in the terminal:

    ```terminal
    pip install flask
    pip install flask-socketio
    pip install bcrypt
    pip install eventlet
    ```


## How to run the code?

    ```terminal
    python main.py
    ```

Then type in the browser: **https://your_IPv4_address:5000**
To get you IP enter **ipconfig** in **cmd**.


## How to view and edit the code?

1. Open the project's folder in vs code (if you don't have VS Code installed, download it from the official website).

2. Install required extensions:
    - Go to **Extensions** (Ctrl + Shift + X)
    - Search for and install: **Python**

---

**GitHub repository: https://github.com/TechWithBar/chat_app**
**Programed by: Bar Fishilevich**