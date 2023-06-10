import socket
import json
import base64
import rsa
import os
from hashlib import sha256

import os
import struct

import os
import struct

    
def load_public_key_from_file(filename):
    try:
        with open(filename, 'r') as f:
            key_data = f.read()
            print("\033[34m" + f"Loaded public key from {filename}" + "\033[0m")  # Blue
            return key_data  # return the key as a string
    except Exception as e:
        print("\033[31m" + f"Error loading public key from file {filename}: {str(e)}" + "\033[0m")  # Red
        return None

# Load the staff data from staff.json
with open('staff.json', 'r') as file:
    staff_data = json.load(file)
    staff_keys = {load_public_key_from_file(member['public_key_file']): member['role'] for member in staff_data['staff']}


class AttributeCertificate:
    def __init__(self, holder_public_key, role):
        self.version = "1.0"
        self.holder = holder_public_key
        self.issuer = "Attribute Certificate Issuer"
        self.signature_algorithm = "RSA-SHA256"
        self.serial_number = "123456789"
        self.validity_period = "2023-06-01 to 2024-06-01"
        self.attributes = [role]  # Assign the role from staff.json to attributes
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
        _, private_key = rsa.newkeys(2048)

        # Sign the hash value with the issuer's private key
        signature = rsa.sign(hash_value, private_key, 'SHA-256')

        # Convert the signature to a Base64-encoded string
        self.signature_value = base64.b64encode(signature).decode()

        print("\033[36m" + "Generated signature for attribute certificate." + "\033[0m")  # Cyan

# Create an empty dictionary to store Attribute Certificates
ac_dict = {}

import threading

def send_ac_to_repo(ac_json_data):
    repo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    repo_socket.connect(('localhost', 6000))  # Connect to repo_ac server
    ac_json_data = ac_json_data.encode('utf-8')
    ac_json_data = len(ac_json_data).to_bytes(4, 'big') + ac_json_data
    repo_socket.sendall(ac_json_data)
    print("\033[35m" + "Sending Attribute Certificate to repo_ac server." + "\033[0m")  # Magenta
    # Receive response from repo_ac server
    #response = repo_socket.recv(4096).decode()


def file_exists(filename):
    return os.path.isfile(filename)

import struct

def unpack_id_pub_file(packed_data):
    # Read the packed file size as 4-byte unsigned integer
    packed_size = packed_data[-4:]
    file_size = struct.unpack('!I', packed_size)[0]

    # Remove the packed file size from the data
    packed_data = packed_data[:-4]

    # Calculate the number of remaining bytes to read
    remaining_bytes = file_size - len(packed_data)

    # Yield the packed data
    yield packed_data

    # Yield any remaining bytes
    if remaining_bytes > 0:
        yield packed_data[:remaining_bytes]


def handle_client(client_socket):
    # Receive the holder's public key from the client
    holder_public_key = client_socket.recv(4096).decode('utf-8')
    role = staff_keys.get(holder_public_key, None)
    if role is None:
        client_socket.send("ac ko".encode())
        print("Public key not associated with any role. Unable to generate AC.")
        client_socket.close()
        return

    print("\033[33m" + f"Received public key: {holder_public_key}" + "\033[0m")  # Yellow
    print("\033[33m" + f"User role: {role}" + "\033[0m")  # Yellow

    # Check if an Attribute Certificate already exists for this public key
    if holder_public_key in ac_dict:
        attribute_certificate = ac_dict[holder_public_key]
    else:
        # If not, create an Attribute Certificate
        attribute_certificate = AttributeCertificate(holder_public_key, role)

        # Generate the signature for the Attribute Certificate
        attribute_certificate.generate_signature()

        # Store the Attribute Certificate in the dictionary
        ac_dict[holder_public_key] = attribute_certificate
        print("\033[32m" + "Generated Attribute Certificate and stored in the dictionary." + "\033[0m")  # Green


    # Convert the Attribute Certificate to a JSON string
    json_data = json.dumps(attribute_certificate.to_dict())

    # Send the JSON data to the client
    client_socket.send('ac ok'.encode())
    print("\033[32m" + "Sent response to client." + "\033[0m")  # Green


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
    print("\033[36m" + 'Server listening on localhost:5000' + "\033[0m")  # Cyan


    try:
        while True:
            # Accept a client connection
            client_socket, client_address = server_socket.accept()

            # Handle the client request in a new thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
            print("\033[33m" + f"Accepted connection from {client_address}" + "\033[0m")  # Yellow
            print("\033[36m" + f"Started a new thread to handle the client request." + "\033[0m")  # Cyan
    except KeyboardInterrupt:
        print("\033[31m" + "\nShutting down the server." + "\033[0m")  # Red
        server_socket.close()

run_server()
