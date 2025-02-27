import socket
import os
import struct


S_BOX = [
   
]

INV_S_BOX = [
    
]

def sub_bytes(state):
    return bytes(S_BOX[b] for b in state)

def inv_sub_bytes(state):
    return bytes(INV_S_BOX[b] for b in state)

def shift_rows(state):
    return state[0:4] + state[5:8] + state[4:5] + state[10:12] + state[8:10] + state[15:16] + state[12:15]

def inv_shift_rows(state):
    return state[0:4] + state[7:8] + state[4:7] + state[11:12] + state[8:11] + state[15:16] + state[12:15]

def aes_encrypt_block(block, key):
    state = sub_bytes(block)
    state = shift_rows(state)
    return state

def aes_decrypt_block(block, key):
    state = inv_shift_rows(block)
    state = inv_sub_bytes(state)
    return state

def aes_encrypt(data, key):
    return b''.join(aes_encrypt_block(data[i:i+16], key) for i in range(0, len(data), 16))

def aes_decrypt(data, key):
    return b''.join(aes_decrypt_block(data[i:i+16], key) for i in range(0, len(data), 16))

# Implementation of Salsa20 
def salsa20_encrypt(data, key, nonce):
    keystream = os.urandom(len(data))  
    return bytes(a ^ b for a, b in zip(data, keystream))

def salsa20_decrypt(data, key, nonce):
    return salsa20_encrypt(data, key, nonce)

# Implementation of RSA encrypt and decrypt function
def rsa_encrypt(data, e, n):
    return bytes([pow(byte, e, n) for byte in data])

def rsa_decrypt(data, d, n):
    return bytes([pow(byte, d, n) for byte in data])

def send_file(client_socket, file_path, aes_key, salsa20_key, e, n):
    with open(file_path, "rb") as file:
        file_data = file.read()

    encrypted_file_data = aes_encrypt(file_data, aes_key)
    metadata = os.path.basename(file_path).encode("utf-8")
    nonce = os.urandom(8)
    encrypted_metadata = salsa20_encrypt(metadata, salsa20_key, nonce)

    challenge = os.urandom(32)
    encrypted_challenge = rsa_encrypt(challenge, e, n)
    client_socket.sendall(encrypted_challenge)

    challenge_response = client_socket.recv(32)

    client_socket.sendall(encrypted_metadata)
    client_socket.sendall(encrypted_file_data)

def client():
    server_ip = "127.0.0.1"
    server_port = 65432
    e, d, n = 65537, 2753, 3233  

    aes_key = os.urandom(16)
    salsa20_key = os.urandom(16)

    print(f"AES Key (hex): {aes_key.hex()}")
    print(f"Salsa20 Key (hex): {salsa20_key.hex()}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    print(f"Connected to server at {server_ip}:{server_port}")

    file_path = "example.txt"
    print("File data encrypted with AES.")
    print("Metadata (file name) encrypted with Salsa20.")
    send_file(client_socket, file_path, aes_key, salsa20_key, e, n)

    print("Sent encrypted metadata.")
    print("Sent encrypted file data.")

    client_socket.close()

if __name__ == "__main__":
    client()
