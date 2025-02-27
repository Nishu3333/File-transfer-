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

# Salsa20 Implementation
def salsa20_encrypt(data, key, nonce):
    keystream = os.urandom(len(data))  # Placeholder (generate real keystream with Salsa20 core)
    return bytes(a ^ b for a, b in zip(data, keystream))

def salsa20_decrypt(data, key, nonce):
    return salsa20_encrypt(data, key, nonce)

# RSA Implementation
def rsa_encrypt(data, e, n):
    return [pow(byte, e, n) for byte in data]

def rsa_decrypt(data, d, n):
    return bytes([pow(byte, d, n) for byte in data])

def server():
    server_ip = "127.0.0.1"
    server_port = 65432
    e, d, n = 65537, 2753, 3233  # Example RSA keys (use real keygen in practice)

    print(f"Server listening on {server_ip}:{server_port}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        challenge = client_socket.recv(32)
        challenge_response = rsa_decrypt(challenge, d, n)
        client_socket.sendall(challenge_response)

        encrypted_metadata = client_socket.recv(1024)
        encrypted_file_data = client_socket.recv(4096)

        aes_key = bytes.fromhex(input("Enter AES key (hex): "))
        salsa20_key = bytes.fromhex(input("Enter Salsa20 key (hex): "))
        nonce = os.urandom(8)

        decrypted_metadata = salsa20_decrypt(encrypted_metadata, salsa20_key, nonce)
        file_name = decrypted_metadata.decode(errors='ignore').strip()

        decrypted_file_data = aes_decrypt(encrypted_file_data, aes_key)
        with open(f"decrypted_{file_name}", "wb") as file:
            file.write(decrypted_file_data)

        print(f"Decrypted file saved as decrypted_{file_name}")
        client_socket.close()

if __name__ == "__main__":
    server()
