import socket
import threading
from crypto_utils import generate_rsa_key_pair, encrypt_message, decrypt_message, encrypt_aes_key, decrypt_aes_key
from Crypto.Random import get_random_bytes
private_key, public_key = generate_rsa_key_pair()
HOST = '0.0.0.0'
PORT = 5000

clients = {}
client_keys = {}


def handle_client(client_socket):
    global clients, client_keys
    while True:
        try:
            encrypted_message = client_socket.recv(2048)
            if not encrypted_message:
                break
            aes_key = client_keys[client_socket]
            decrypted_message = decrypt_message(encrypted_message, aes_key)
            broadcast(decrypted_message, client_socket)
        except:
            clients.pop(client_socket)
            client_socket.close()
            break


def broadcast(message, sender_socket):
    for client in clients:
        if client != sender_socket:
            aes_key = client_keys[client]
            encrypted_message = encrypt_message(message, aes_key)
            client.send(encrypted_message)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)
print(f"Server started on {HOST}:{PORT}")

while True:
    client_socket, addr = server_socket.accept()
    clients[client_socket] = addr

    client_public_key = client_socket.recv(2048)
    aes_key = get_random_bytes(16)
    encrypted_aes_key = encrypt_aes_key(aes_key, client_public_key)
    client_socket.send(encrypted_aes_key)
    client_keys[client_socket] = aes_key

    client_thread = threading.Thread(
        target=handle_client, args=(client_socket,))
    client_thread.start()
