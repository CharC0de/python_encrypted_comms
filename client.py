import os
from dotenv import load_dotenv
import socket
import threading
from crypto_utils import generate_rsa_key_pair, encrypt_message, decrypt_message, encrypt_aes_key, decrypt_aes_key

load_dotenv()
host = os.getenv('HOST', 'localhost')
port = int(os.getenv('PORT', 5000))


def receive_messages(client_socket, aes_key):
    while True:
        try:
            encrypted_message = client_socket.recv(2048)
            if not encrypted_message:
                break
            message = decrypt_message(encrypted_message, aes_key)
            print(f"\rReceived: {message}\n> ", end="")
        except:
            print("Disconnected from server.")
            client_socket.close()
            break


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

private_key, public_key = generate_rsa_key_pair()
client_socket.send(public_key)

encrypted_aes_key = client_socket.recv(2048)
aes_key = decrypt_aes_key(encrypted_aes_key, private_key)

print("Connected to server. Type your messages below.")

receive_thread = threading.Thread(
    target=receive_messages, args=(client_socket, aes_key))
receive_thread.start()

while True:
    message = input("> ")
    if message.lower() == 'exit':
        break
    encrypted_message = encrypt_message(message, aes_key)
    client_socket.send(encrypted_message)

client_socket.close()
