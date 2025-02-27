# File-transfer-
#Overview
A secure file transfer system using RSA, AES, and Salsa20 encryption.
Ensures authentication, confidentiality, and integrity of transmitted files.
#Security Features
1. Authentication: RSA is used for client authentication.
2. Confidentiality: AES encrypts file contents, and Salsa20 encrypts metadata (filename).
3. Integrity: Proper decryption ensures data validity.
#Technologies Used
Python has been implemented as the programming language to build this project. 
Socket Programming (for client-server communication).
Manual implementation of RSA, AES-128 , and Salsa20.
#How It Works
Client:
Encrypts file data using AES.
Encrypts metadata using Salsa20.
Sends RSA authentication to the server.
Transmits encrypted file and metadata.
Server:
Authenticates the client using RSA.
Receives encrypted metadata and file.
Requests AES & Salsa20 keys from the user.
Decrypts the received data and saves the file.
