# Hybrid‑Server

**Hybrid‑Server** is an educational messaging system that demonstrates the combination of asymmetric and symmetric encryption in a client–server architecture.  The project consists of a GUI client written with PyQt6 and a multithreaded server using Python’s socket module.  During the connection handshake the client and server perform a Diffie–Hellman key exchange and RSA public‑key exchange, then switch to AES for encrypting all subsequent messages.

## Key Concepts

* **User management** – the server stores users in a pickle file and supports sign‑up and login requests.  Passwords are hashed with a salt before storage and verified on login.
* **Hybrid cryptography** – the client and server exchange RSA public keys to securely transmit an AES key.  Diffie–Hellman is used to derive a shared secret, which is then hashed to produce an AES key and IV.  Messages are encrypted/decrypted using AES in CBC mode via functions in `TCP_AES.py`.
* **Asynchronous messages** – the server maintains a thread‑safe dictionary of message queues for each connected client using the `AsyncMessages` class.  This allows threads handling different clients to communicate without locking the entire server【166510938047340†screenshot】.
* **Custom protocol** – communication uses 3‑letter request codes (e.g. `LGN` for login, `SNU` for sign‑up, `GSR` for get server RSA key) and a size‑prefixed framing implemented in `tcp_by_size.py`.  The server parses requests and dispatches actions such as sending messages, retrieving users, or returning the server RSA key.

## Repository Contents

* **`gui_srv.py`** – the main server.  It listens on a TCP socket, handles login and sign‑up requests, performs the RSA/AES handshake and routes encrypted messages between clients.  User data is stored in `users_data.pkl`.  The server also supports requests to send messages to other clients and to retrieve the server RSA key.
* **`gui_cli.py`** – a PyQt6 GUI client.  It displays fields for entering the server IP, username, password, Diffie–Hellman parameter and RSA key size.  Buttons allow the user to connect, sign up, log in and send messages.  Once connected, the client encrypts requests with AES and decrypts responses, updating the UI accordingly.
* **`RSA.py`** – implements RSA key generation, encryption and decryption using PyCryptodome.  It wraps RSA key generation, allows setting a peer’s public key and converting keys to/from Base64.
* **`TCP_AES.py`** – provides `Encrypt_AES` and `Decrypt_AES` functions that pad data, generate an IV and perform AES encryption/decryption using CBC mode.
* **`AES_Decryption.py`** – helpers to send and receive data encrypted with AES over a socket.  It wraps `tcp_by_size.send_with_size()` and `recv_by_size()` to include AES encryption/decryption.
* **`AsyncMessages.py`** – a thread‑safe message queue manager used by the server.  It allows multiple threads to push and pop messages associated with a client socket.

## Running the Project

### Prerequisites

* Python 3.x
* PyQt6 (`pip install PyQt6`)
* PyCryptodome (`pip install pycryptodome`)

### Steps

1. **Start the server:**

   ```bash
   python3 gui_srv.py
   ```

   The server will create a `users_data.pkl` file to store user credentials and RSA keys.  It listens on port 5002 by default.

2. **Run the client:**

   ```bash
   python3 gui_cli.py
   ```

   Enter the server IP, choose RSA key size (e.g. 1024), a Diffie–Hellman parameter, your username and password and press **Sign Up** or **Log In**.  Once authenticated, you can send messages to other connected users.  The client displays incoming messages and the connection status.

## Notes

* This project is for educational purposes and is not hardened for production.  It demonstrates how to combine RSA and AES to secure a chat application, but it lacks certificate verification, authentication of Diffie–Hellman parameters and replay protection.
* Because the client uses PyQt6, it must be run in an environment with a graphical display.
