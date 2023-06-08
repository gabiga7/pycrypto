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
        self.attributes = ac_dict['attributes']
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



def compare_keys(key1, key2):
    print("First few characters of key1:")
    for char in key1[:10]:
        print(f"{char}: {ord(char)}")
    print("First few characters of key2:")
    for char in key2[:10]:
        print(f"{char}: {ord(char)}")
    if len(key1) != len(key2):
        print("Keys are of different lengths.")
        return
    for i in range(len(key1)):
        if key1[i] != key2[i]:
            print(f"Difference at position {i}: {key1[i]} ({ord(key1[i])}) vs {key2[i]} ({ord(key2[i])})")

def is_rsa_key_in_dict(key, key_dict):
    key = key.strip()  # Removing leading and trailing whitespaces
    for dict_key in key_dict.keys():
        dict_key = dict_key.strip().replace("\r\n", "\n")
        if key != dict_key:
            print(f"Comparing ***{key}*** with ***{dict_key}***")
            compare_keys(key, dict_key)
            print("Keys are not identical")
        else:
            print("Keys are identical")
            return True
    return False

def find_matching_key(needle, haystack):
    needle = needle.strip()  # Strip leading/trailing whitespaces
    for key in haystack.keys():
        stripped_key = key.strip().replace("\r\n", "\n")  # Treat the key similarly to needle
        if needle == stripped_key:
            return key  # return the original (untreated) key
    return None  # return None if no match is found


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
    print("Handling a new client connection...")
    while True:
        request = recv_msg(client_socket)  # Receive AC JSON data or public key
        #print(f"Received request from client: {request}")  # Debug: print request data
        if not request:
            break

        if 'holder' in request:
            # This is an AC
            ac_dict_json = json.loads(request)
            public_key = ac_dict_json['holder']  # Get holder's public key from AC dict
            print(f"Received AC for public key: {public_key}")

            if public_key not in ac_dict:
                ac = AttributeCertificate(public_key)
                ac.from_dict(ac_dict_json)
                ac_dict[public_key] = ac  # Store the AC
                print(f'Stored AC')
                print(json.dumps(ac.to_dict(), indent=4))  # Debug: print stored certificate

            client_socket.send("AC received and stored successfully.".encode())
            print("Sent response to ac_issuer.")
        else:
            # This is a public key
            dict_key = find_matching_key(request, ac_dict)
            if dict_key is not None:  # if a match is found in the dictionary
                ac = ac_dict[dict_key]
                encoded_ac_data = json.dumps(ac.to_dict()).encode()
                print(f"Encoded AC data: {encoded_ac_data}")  # Debug: print encoded AC data

                ac_data_length = len(encoded_ac_data).to_bytes(4, 'big')
                client_socket.sendall(ac_data_length + encoded_ac_data)
                print("Sent AC to client.")
            else:
                client_socket.send("No AC associated with this public key.".encode())
                print("No AC associated with this public key.")
    client_socket.close()
    print("Client connection closed.")

if __name__ == "__main__":
    HOST, PORT = "localhost", 6000

    # Create the server, binding to localhost on port 6000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from: {addr}")
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        server_socket.close()
        print("Server shut down.")
