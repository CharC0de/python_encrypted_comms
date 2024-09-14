import socket
import threading

# List to store connected clients
clients = []

# Function to broadcast a message to all clients


def broadcast(message, conn):
    for client in clients:
        if client != conn:  # Send to all except the sender
            try:
                client.send(message.encode())
            except:
                # Handle error and remove the client if it disconnects
                client.close()
                clients.remove(client)

# Function to handle each client connection


def handle_client(conn, address):
    print(f"New connection from: {address}")
    conn.send("Welcome to the server!".encode())

    while True:
        try:
            data = conn.recv(1024).decode()
            if not data:
                break
            print(f"Received from {address}: {data}")
            broadcast(f"{address} says: {data}", conn)
        except:
            # If the client disconnects, close connection and remove from list
            print(f"Connection lost from {address}")
            break

    conn.close()
    clients.remove(conn)


def server_program():
    host = "0.0.0.0"
    port = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))

    server_socket.listen(5)  # Listen for up to 5 connections
    print(f"Server is listening on {host}:{port}...")

    try:
        while True:
            conn, address = server_socket.accept()  # Accept a new connection
            clients.append(conn)  # Add the new client to the list
            # Start a new thread for each client
            client_thread = threading.Thread(
                target=handle_client, args=(conn, address))
            client_thread.start()
    except KeyboardInterrupt:
        print("Server is shutting down.")
    finally:
        for client in clients:
            client.close()  # Close all client connections
        server_socket.close()  # Close the server socket


if __name__ == '__main__':
    server_program()
