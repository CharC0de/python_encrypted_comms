import socket


def server_program():
    host = "0.0.0.0"  # Bind to all available interfaces
    port = 5000  # Port for communication

    server_socket = socket.socket()  # Create a socket object
    server_socket.setsockopt(
        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow address reuse
    server_socket.bind((host, port))  # Bind the socket to the address and port

    server_socket.listen(2)  # Allow up to 2 connections
    print(f"Server is listening on {host}:{port}...")

    try:
        while True:
            conn, address = server_socket.accept()  # Accept a new connection
            print(f"Connection from: {address}")

            while True:
                # Receive data from the client
                data = conn.recv(1024).decode()
                if not data:
                    break  # Break the loop if no data is received
                print(f"From connected user: {data}")

                # Send response back to the client
                response = input(" -> ")
                conn.send(response.encode())  # Send the response to the client

            conn.close()  # Close the connection when done
    except KeyboardInterrupt:
        print("Server is shutting down.")
    finally:
        server_socket.close()  # Ensure the socket is closed on exit


if __name__ == '__main__':
    server_program()
