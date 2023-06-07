import socket

# Define the server host and port
HOST = '127.0.0.1'
PORT = 1234

# Sample attribute certificate data (role and access rules)
attribute_certificates = {
    'client1': {
        'role': 'admin',
        'access_rules': ['read', 'write', 'delete']
    },
    'client2': {
        'role': 'user',
        'access_rules': ['read']
    },
    # Add more clients and their attribute certificates as needed
}

# Create a TCP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the host and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen()

print(f"Repository server listening on {HOST}:{PORT}")

while True:
    # Accept a client connection
    client_socket, client_address = server_socket.accept()
    print(f"Client connected from {client_address}")

    # Receive the client's public key certificate (PKC)
    pkc = client_socket.recv(1024).decode()

    # Lookup the attribute certificate (AC) based on the PKC
    ac = attribute_certificates.get(pkc)

    if ac:
        # Send the attribute certificate to the client
        ac_data = f"Role: {ac['role']}\nAccess Rules: {', '.join(ac['access_rules'])}"
        client_socket.send(ac_data.encode())
    else:
        # No AC found for the client
        client_socket.send("No attribute certificate found.".encode())

    # Close the connection
    client_socket.close()
