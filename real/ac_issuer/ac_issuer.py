
import socket
import json
import base64
import rsa
import os
from hashlib import sha256


def load_public_key_from_file(filename):
    try:
        with open(filename, 'r') as f:
            key_data = f.read().strip()
            return key_data  # return the key as a string
    except Exception as e:
        print(f"Error loading public key from file {filename}: {str(e)}")
        return None


# Load the staff data from staff.json
with open('staff.json', 'r') as file:
    staff_data = json.load(file)
    staff_keys = {load_public_key_from_file(member['public_key_file']): member['role'] for member in staff_data['staff']}
    print(staff_keys)  # debug print




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

# Create an empty dictionary to store Attribute Certificates
ac_dict = {}

import threading




def send_ac_to_repo(ac_json_data):
    print("Sending AC to repository...")
    repo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    repo_socket.connect(('localhost', 6000))  # Connect to repo_ac server
    ac_json_data = ac_json_data.encode('utf-8')
    ac_json_data = len(ac_json_data).to_bytes(4, 'big') + ac_json_data
    repo_socket.sendall(ac_json_data)
    # Receive response from repo_ac server
    response = repo_socket.recv(4096).decode()
    print(f'Response from repo_ac: {response}')




def file_exists(filename):
    return os.path.isfile(filename)




def handle_client(client_socket):
    print("Handling a new client connection...")
    # Receive the holder's public key from the client
    holder_public_key_data = client_socket.recv(4096).decode().strip()
    holder_public_key = holder_public_key_data.strip()  # no need to load as rsa.PublicKey

    role = staff_keys.get(holder_public_key, None)
    if role is None:
        print(f"No role found for received public key. Unable to generate AC.")
        client_socket.send("Public key not associated with any role. Unable to generate AC.".encode())
        client_socket.close()
        return

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
        print(f"Stored new AC for public key: {holder_public_key}")

    # Convert the Attribute Certificate to a JSON string
    json_data = json.dumps(attribute_certificate.to_dict())

    # Print the Attribute Certificate
    print("Attribute Certificate:")
    print(json.dumps(attribute_certificate.to_dict(), indent=4))

    # Send the JSON data to the client
    client_socket.send(json_data.encode())
    print("Sent AC to client.")

    # Send the AC to repo_ac
    send_ac_to_repo(json_data)
    
    # Close the client socket
    client_socket.close()
    print("Client connection closed.")



def run_server():
    # Create a TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to localhost and port 5000
    server_socket.bind(('localhost', 5000))

    # Listen for incoming connections
    server_socket.listen(1)
    print('Server listening on localhost:5000')

    try:
        while True:
            # Accept a client connection
            client_socket, client_address = server_socket.accept()
            print(f'Accepted connection from: {client_address}')

            # Handle the client request in a new thread
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down the server.")
        server_socket.close()

run_server()

{
    "staff": [
        {
            "name": "alice_dupont",
            "role": "manager",
            "public_key_file": "alice_dupont.pub"
        },
        {
            "name": "bob_dumas",
            "role": "worker",
            "public_key_file": "bob_dumas.pub"
        }
    ]
}
