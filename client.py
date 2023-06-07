import socket
import sys

# Server host
HOST = 'localhost'

# Get port from command-line argument
if len(sys.argv) < 2:
    print('Usage: python client.py <port>')
    sys.exit(1)

try:
    PORT = int(sys.argv[1])
except ValueError:
    print('Invalid port number')
    sys.exit(1)

# Create a socket object
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server
client_socket.connect((HOST, PORT))

while True:
    # Send data to the server
    data = input('Enter data to send (type "exit" to quit): ')
    client_socket.sendall(data.encode())

    # Check if client wants to exit
    if data.lower() == 'exit':
        break

    # Receive the response from the server
    response = client_socket.recv(1024).decode()
    print('Received response:', response)

# Close the connection
client_socket.close()
