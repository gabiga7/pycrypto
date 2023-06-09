import socket
from rsa.key import newkeys

def generate_public_key():
    # Generate a new RSA key pair
    public_key, private_key = newkeys(2048)

    # Return the public key
    return public_key

def send_public_key(public_key):
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server (localhost:5000)
    server_address = ('localhost', 5000)
    client_socket.connect(server_address)

    # Send the public key to the server
    client_socket.send(public_key.save_pkcs1())

    # Close the client socket
    client_socket.close()

# Example usage
public_key = generate_public_key()
send_public_key(public_key)
