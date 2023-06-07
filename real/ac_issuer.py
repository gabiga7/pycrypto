import socket
import json
import base64
from rsa.key import newkeys
from hashlib import sha256
from rsa import sign

class AttributeCertificate:
    def __init__(self, holder_public_key):
        self.version = "1.0"
        self.holder = holder_public_key
        self.issuer = "Attribute Certificate Issuer"
        self.signature_algorithm = "RSA-SHA256"
        self.serial_number = "123456789"
        self.validity_period = "2023-06-01 to 2024-06-01"
        self.attributes = ["Attribute 1", "Attribute 2"]
        self.signature_value = None

    def to_dict(self):
        return {
            'version': self.version,
            'holder': self.holder,
            'issuer': self.issuer,
            'signature_algorithm': self.signature_algorithm,
            'serial_number': self.serial_number,
            'validity_period': self.validity_period,
            'attributes': self.attributes,
            'signature_value': self.signature_value
        }

    def generate_signature(self):
        # Convert the certificate data to a JSON string
        json_data = json.dumps(self.to_dict(), sort_keys=True)

        # Hash the JSON data using SHA-256
        hash_value = sha256(json_data.encode()).digest()

        # Generate a new RSA key pair
        _, private_key = newkeys(2048)

        # Sign the hash value with the issuer's private key
        signature = sign(hash_value, private_key, 'SHA-256')

        # Convert the signature to a Base64-encoded string
        self.signature_value = base64.b64encode(signature).decode()

# Create an empty dictionary to store Attribute Certificates
ac_dict = {}

"""def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = msg.encode()
    msg = len(msg).to_bytes(4, 'big') + msg
    sock.sendall(msg)"""

def send_ac_to_repo(ac_json_data):
    repo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    repo_socket.connect(('localhost', 6000))  # Connect to repo_ac server
    ac_json_data = ac_json_data.encode()
    ac_json_data = len(ac_json_data).to_bytes(4, 'big') + ac_json_data
    repo_socket.sendall(ac_json_data)


def handle_client(client_socket):
    # Receive the holder's public key from the client
    holder_public_key = client_socket.recv(4096).decode()

    # Check if an Attribute Certificate already exists for this public key
    if holder_public_key in ac_dict:
        attribute_certificate = ac_dict[holder_public_key]
    else:
        # If not, create an Attribute Certificate
        attribute_certificate = AttributeCertificate(holder_public_key)

        # Generate the signature for the Attribute Certificate
        attribute_certificate.generate_signature()

        # Store the Attribute Certificate in the dictionary
        ac_dict[holder_public_key] = attribute_certificate

    # Convert the Attribute Certificate to a JSON string
    json_data = json.dumps(attribute_certificate.to_dict())

    # Print the Attribute Certificate
    print("Attribute Certificate:")
    print(json_data)

    # Send the JSON data to the client
    client_socket.send(json_data.encode())

    # Send the AC to repo_ac
    send_ac_to_repo(json_data)

    # Close the client socket
    client_socket.close()

def run_server():
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to localhost and port 5000
    server_socket.bind(('localhost', 5000))

    # Listen for incoming connections
    server_socket.listen(1)
    print('Server listening on localhost:5000')

    while True:
        # Accept a client connection
        client_socket, client_address = server_socket.accept()
        print('Accepted connection from:', client_address)

        # Handle the client request
        handle_client(client_socket)

run_server()
