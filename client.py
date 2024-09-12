import os
import base64
from dotenv import load_dotenv
import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

# Load environment variables from .env file
load_dotenv()

# Retrieve socket connection details from environment variables
host = os.getenv('HOST')
port = int(os.getenv('PORT'))

# Load RSA keys from environment variables
private_key_pem = os.getenv('RSA_PRIVATE_KEY').encode()
public_key_pem = os.getenv('RSA_PUBLIC_KEY').encode()

# Load RSA keys
private_key = serialization.load_pem_private_key(
    private_key_pem, password=None)
public_key = serialization.load_pem_public_key(public_key_pem)

# Function to encrypt AES key using RSA public key


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

# Function to decrypt AES key using RSA private key


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

# Function to encrypt message using AES


def aes_encrypt(plaintext, aes_key):
    # AES needs a random Initialization Vector (IV)
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

# Function to decrypt message using AES


def aes_decrypt(ciphertext, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def client_program():
    # Establish socket connection
    client_socket = socket.socket()  # Create a socket object
    client_socket.connect((host, port))  # Connect to the server

    # Generate a random AES key
    aes_key = secrets.token_bytes(32)  # 256-bit AES key

    # Encrypt the AES key with the server's public RSA key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key)

    # Send encrypted AES key to the server
    client_socket.send(base64.b64encode(encrypted_aes_key)
                       )  # Send as Base64 encoded string

    # Receive the server's response with AES key (assuming server also sends an encrypted AES key)
    server_encrypted_aes_key = base64.b64decode(client_socket.recv(1024))
    decrypted_aes_key = decrypt_aes_key_with_rsa(server_encrypted_aes_key)

    message = input(" -> ")  # Get user input

    while message.lower().strip() != 'exit':
        # Encrypt the message with AES key
        iv, encrypted_message = aes_encrypt(message.encode(), aes_key)

        # Send IV and encrypted message
        client_socket.send(base64.b64encode(iv) + b'::' +
                           base64.b64encode(encrypted_message))

        # Receive response from the server
        data = client_socket.recv(1024).split(b'::')
        iv, encrypted_response = base64.b64decode(
            data[0]), base64.b64decode(data[1])

        # Decrypt the response
        decrypted_response = aes_decrypt(
            encrypted_response, decrypted_aes_key, iv)
        print(f"Received from server: {decrypted_response.decode()}")

        message = input(" -> ")  # Get new input

    client_socket.close()  # Close the connection


if __name__ == '__main__':
    client_program()
