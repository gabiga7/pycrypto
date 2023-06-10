import json
import socket
import threading

# Function to load the Access Control List (ACL) from a JSON file
def load_acl(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load the Access Control List (ACL) from the file
acl = load_acl("access_control_list.json")
global norole
norole=False


def retrieve_ac(public_key):
    repo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    repo_socket.connect(('localhost', 6000))  # Connect to repo_ac server
    print("\033[94mConnected to the repo_ac server.\033[0m")  # Blue

    # Encode public key and get its length
    encoded_public_key = public_key.encode()
    public_key_length = len(encoded_public_key).to_bytes(4, 'big')

    # Send public key length and public key to repo_ac
    repo_socket.sendall(public_key_length + encoded_public_key)
    print("\033[92mSent public key to the repo_ac server.\033[0m")  # Green

    # Receive the length of roles
    roles_data_length = int.from_bytes(repo_socket.recv(4), 'big')
    # Receive the roles
    roles_json = repo_socket.recv(roles_data_length).decode()

    # Check if 'ko' was received
    if roles_json.strip() == 'ko':
        print("\033[31mNo AC associated with this public key.\033[0m")  # Red
        return []  # No AC associated with the public key

    if roles_json:
        try:
            roles = json.loads(roles_json)
            print("\033[92mReceived roles associated with the public key.\033[0m")  # Green
        except:
            print("\033[31mError in parsing roles.\033[0m")  # Red
    return roles

def handle_client(client_socket):
    print("\033[94mHandling a new client connection...\033[0m")  # Blue

    # Receive the client's public key
    public_key = client_socket.recv(4096).decode('utf-8')
    print(f"\033[92mReceived public key from client: {public_key[:10]}...\033[0m")  # Green

    # Retrieve the roles associated with this public key
    roles = retrieve_ac(public_key)

    if norole:
        client_socket.send('ko'.encode())
        print("\033[31mClient is not authorized to use this service as no role was found.\033[0m")  # Red
        return

    # Flattened roles from dictionary to list
    flat_roles = sum(roles.values(), [])

    # Initialize access as False
    access = False

    # Check each role in the ACL
    for role, acl_access in acl.items():
        # If role is found and access is granted, set access to True
        if role in flat_roles and acl_access["access"]:
            access = True
            print("\033[92mAccess granted to client.\033[0m")  # Green
            break  # No need to check other roles

    if access:
        client_socket.send('ok'.encode())
        print("\033[32mClient is authorized to use this service.\033[0m")  # Green
        while True:
            # Receive calculation from client
            operation = client_socket.recv(4096).decode()

            # Break the loop and close the connection if client disconnects
            if operation == "":
                break

            # Perform the calculation
            try:
                result = str(eval(operation))
                client_socket.send(result.encode())
                print(f"\033[92mSent calculation result to client: {result}\033[0m")  # Green
            except Exception as e:
                client_socket.send(str(e).encode())
                print("\033[31mError in performing calculation.\033[0m")  # Red
    else:
        client_socket.send('ko'.encode())
        print("\033[31mClient is not authorized to use this service.\033[0m")  # Red

    client_socket.close()
    print("\033[94mClosed client connection.\033[0m")  # Blue

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 5001))
    server_socket.listen(1)
    print('\033[94mServer listening on localhost:5001\033[0m')  # Blue

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"\033[92mAccepted connection from {client_address}\033[0m")  # Green
            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()
    except KeyboardInterrupt:
        print("\033[31mServer shut down.\033[0m")  # Red
        server_socket.close()

run_server()
