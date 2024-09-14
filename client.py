import socket


def client_program():
    host = 'localhost'
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    # Receive welcome message from server
    message = client_socket.recv(1024).decode()
    print(f"Server: {message}")

    message = input(" -> ")  # Get input from the user

    while message.lower().strip() != 'exit':
        client_socket.send(message.encode())  # Send message to server
        data = client_socket.recv(1024).decode()  # Receive response

        print(f"Received from server: {data}")

        message = input(" -> ")  # Get new input

    client_socket.close()  # Close the connection


if __name__ == '__main__':
    client_program()
