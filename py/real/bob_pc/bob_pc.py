import socket
from rsa.key import newkeys
import sys
import os
from rsa import PublicKey

def generate_public_key():
    public_key_file = "id.pub"
    private_key_file = "id.pem"

    # Check if the public key file exists
    if os.path.isfile(public_key_file):
        # If it exists, read it and return the public key as a string
        with open(public_key_file, 'r') as f:
            public_key_data = f.read().replace('\n', '')
            print("\033[34m" + "Public key successfully loaded from file." + "\033[0m")  # Blue
            return public_key_data
    else:
        # If it does not exist, generate a new RSA key pair
        print("\033[36m" + "Generating a new RSA key pair..." + "\033[0m")  # Cyan
        public_key, private_key = newkeys(2048)

        # Save the public key to a file
        with open(public_key_file, 'w') as f:
            f.write(public_key.save_pkcs1().decode().replace('\n', ''))
        print("\033[32m" + "Public key saved to file." + "\033[0m")  # Green

        # Save the private key to a file
        with open(private_key_file, 'w') as f:
            f.write(private_key.save_pkcs1().decode().replace('\n', ''))
        print("\033[32m" + "Private key saved to file." + "\033[0m")  # Green

        # Return the public key as a string
        return public_key.save_pkcs1().decode().replace('\n', '')

def send_public_key_file(server_port):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    server_address = ('localhost', server_port)
    client_socket.connect(server_address)
    print("\033[33m" + f"Connected to the server at {server_address}" + "\033[0m")  # Yellow

    # Send the public key file content as UTF-8 string to the server
    with open("id.pub", "r") as file:
        public_key_file_content = file.read().replace('\n', '').encode('utf-8')
        client_socket.send(public_key_file_content)
        print("\033[35m" + "Public key sent to server." + "\033[0m")  # Magenta

    return client_socket

def send_operation(client_socket):
    # Send an empty string to ask for permissions
    client_socket.send("".encode())
    response = client_socket.recv(4096).decode()

    # Check the server response
    if response == 'ok':
        print("\033[32m" + f"Access granted by server. Ready to perform operations." + "\033[0m")  # Green
        while True:
            operation = input("Enter operation (or 'exit' to quit): ")
            if operation.lower() == 'exit':
                break
            # Send the calculation to the server
            client_socket.send(operation.encode())
            response = client_socket.recv(4096).decode()
            print(f"Response: {response}")
    elif response == 'ac ok':
        print("\033[34m" + "AC created." + "\033[0m")  # Blue
    else:
        print("\033[31m" + 'Access denied.' + "\033[0m")  # Red

# Example usage
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python alice_pc.py <server_port>")
        exit(1)

    server_port = int(sys.argv[1])
    public_key = generate_public_key()
    client_socket = send_public_key_file(server_port)

    send_operation(client_socket)

    client_socket.close()
