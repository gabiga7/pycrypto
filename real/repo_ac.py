import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode

# AttributeCertificate class
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
        hash_value = SHA256.new(json_data.encode())

        # Generate a new RSA key pair
        key = RSA.generate(2048)

        # Sign the hash value with the issuer's private key
        signature = pkcs1_15.new(key).sign(hash_value)

        # Convert the signature to a Base64-encoded string
        self.signature_value = b64encode(signature).decode()

ac_dict = {}

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = int.from_bytes(raw_msglen, 'big')
    # Read the message
    return recvall(sock, msglen).decode()

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data

def handle_client(client_socket):
    while True:
        ac_json_data = recv_msg(client_socket)  # Receive AC JSON data
        if not ac_json_data:
            break

        ac_dict_json = json.loads(ac_json_data)  # Convert AC JSON data to dict
        public_key = ac_dict_json['holder']  # Get holder's public key from AC dict

        if public_key not in ac_dict:
            ac = AttributeCertificate(public_key)
            ac.version = ac_dict_json['version']
            ac.issuer = ac_dict_json['issuer']
            ac.signature_algorithm = ac_dict_json['signature_algorithm']
            ac.serial_number = ac_dict_json['serial_number']
            ac.validity_period = ac_dict_json['validity_period']
            ac.attributes = ac_dict_json['attributes']
            ac.signature_value = ac_dict_json['signature_value']
            ac_dict[public_key] = ac  # Store the AC

    client_socket.close()

if __name__ == "__main__":
    HOST, PORT = "localhost", 6000

    # Create the server, binding to localhost on port 6000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)

    try:
        while True:
            client_socket, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        server_socket.close()