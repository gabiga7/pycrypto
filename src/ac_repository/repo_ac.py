import socket
import threading
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
import rsa 

# AttributeCertificate class
class AttributeCertificate:
    def __init__(self, holder_public_key):
        self.version = None
        self.holder = holder_public_key
        self.issuer = None
        self.signature_algorithm = None
        self.serial_number = None
        self.validity_period = None
        self.attributes = None
        self.signature_value = None

    def from_dict(self, ac_dict):
        self.version = ac_dict['version']
        self.issuer = ac_dict['issuer']
        self.signature_algorithm = ac_dict['signature_algorithm']
        self.serial_number = ac_dict['serial_number']
        self.validity_period = ac_dict['validity_period']
        self.attributes = {'roles': ac_dict['attributes']}
        self.signature_value = ac_dict['signature_value']

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

ac_dict = {}

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = int.from_bytes(raw_msglen, 'big')
    # Read the message
    return recvall(sock, msglen).decode()


def print_ac(ac):
    ac_dict = ac.to_dict()
    print("Attribute Certificate:")
    for key, value in ac_dict.items():
        # Only print first 10 characters if value is a string, else print the whole value
        printable_value = value[:10]+"..." if isinstance(value, str) and len(value) > 10 else value
        print(f"  {key}: {printable_value}")

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
    print("\033[94mHandling a new client connection...\033[0m")  # Blue
    while True:
        request = recv_msg(client_socket)  # Receive AC JSON data or public key
        if not request:
            break

        if 'holder' in request:
            # This is an AC
            ac_dict_json = json.loads(request)
            public_key = ac_dict_json['holder']  # Get holder's public key from AC dict
            print("\033[93mReceived AC\033[0m")  # Yellow

            if public_key not in ac_dict:
                ac = AttributeCertificate(public_key)
                ac.from_dict(ac_dict_json)
                ac_dict[public_key] = ac  # Store the AC
                print("\033[32mStored AC\033[0m")  # Green
                print_ac(ac)  # Debug: print stored certificate
        else:
            # This is a public key
            if request in ac_dict:  # Simple key match check
                ac = ac_dict[request]

                roles = ac.attributes
                roles_json = json.dumps(roles)  # Convert roles to JSON
                print(f"\033[33mAssociated role found: {roles}\033[0m")  # Yellow

                roles_data_length = len(roles_json).to_bytes(4, 'big')
                client_socket.sendall(roles_data_length + roles_json.encode())
                print("\033[92mSent roles to client.\033[0m")  # Light green
            else:
                roles = {"roles": ["None"] }
                roles_json = json.dumps(roles)
                roles_data_length = len(roles_json).to_bytes(4, 'big')
                client_socket.sendall(roles_data_length + roles_json.encode())
                print("\033[31mNo AC associated with this public key, sent None role.\033[0m")  # Red
    client_socket.close()
    print("\033[32mClient connection closed.\033[0m")  # Green

if __name__ == "__main__":
    HOST, PORT = "localhost", 6000

    # Create the server, binding to localhost on port 6000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"\033[94mServer listening on {HOST}:{PORT}\033[0m")  # Blue

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"\033[92mAccepted connection from: {addr}\033[0m")  # Light green
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        server_socket.close()
        print("\033[31mServer shut down.\033[0m")  # Red
