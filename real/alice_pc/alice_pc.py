import socket
from rsa.key import newkeys
import sys
import os
from rsa import PrivateKey, PublicKey

def generate_public_key():
    public_key_file = "id.pub"
    private_key_file = "id.pem"

    # Check if the public key file exists
    if os.path.isfile(public_key_file):
        # If it exists, read it and return the public key
        with open(public_key_file, 'r') as f:
            public_key_data = f.read()
            return PublicKey.load_pkcs1(public_key_data)
    else:
        # If it does not exist, generate a new RSA key pair
        public_key, private_key = newkeys(2048)

        # Save the public key to a file
        with open(public_key_file, 'w') as f:
            f.write(public_key.save_pkcs1().decode())

        # Save the private key to a file
        with open(private_key_file, 'w') as f:
            f.write(private_key.save_pkcs1().decode())

        # Return the public key
        return public_key

def send_public_key_file(server_port):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    server_address = ('localhost', server_port)
    client_socket.connect(server_address)

    # Send the public key file to the server
    with open("id.pub", "rb") as file:
        public_key_file_content = file.read()
        client_socket.send(public_key_file_content)

    return client_socket

def send_operation(client_socket, operation):
    client_socket.send(operation.encode())
    response = client_socket.recv(4096).decode()
    print(f"Response: {response}")

# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python alice_pc.py <server_port>")
        exit(1)

    server_port = int(sys.argv[1])
    public_key = generate_public_key()
    client_socket = send_public_key_file(server_port)

    while True:
        operation = input("Enter operation (or 'exit' to quit): ")
        if operation.lower() == 'exit':
            break
        send_operation(client_socket, operation)

    client_socket.close()
