import os
import base64
import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get host and port from environment variables
host = os.getenv('HOST', 'localhost')
port = int(os.getenv('PORT', 5000))

# Load RSA keys from PEM files


def load_rsa_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None  # Add password if necessary
        )
    return private_key


def load_rsa_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    return public_key


# Load the private and public keys from .pem files
private_key = load_rsa_private_key("./private_key.pem")
public_key = load_rsa_public_key("./public_key.pem")

# Encrypt AES key using RSA public key


def encrypt_aes_key_with_rsa(aes_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_aes_key

# Decrypt AES key using RSA private key


def decrypt_aes_key_with_rsa(encrypted_aes_key):
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Encrypt message using AES


def aes_encrypt(plaintext, aes_key):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

# Decrypt message using AES


def aes_decrypt(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Client-side program


def client_program():
    client_socket = socket.socket()
    client_socket.connect((host, port))

    aes_key = secrets.token_bytes(32)

    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key)

    client_socket.send(base64.b64encode(encrypted_aes_key))

    message = input(" -> ")

    while message.lower().strip() != 'exit':
        iv, encrypted_message = aes_encrypt(message.encode(), aes_key)

        client_socket.send(base64.b64encode(iv) + b'::' +
                           base64.b64encode(encrypted_message))

        data = client_socket.recv(1024).split(b'::')
        iv, encrypted_response = base64.b64decode(
            data[0]), base64.b64decode(data[1])

        decrypted_response = aes_decrypt(encrypted_response, aes_key, iv)
        print(f"Received from server: {decrypted_response.decode()}")

        message = input(" -> ")

    client_socket.close()


if __name__ == '__main__':
    client_program()
